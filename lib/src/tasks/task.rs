use crate::script::Script;
use crate::tasks::{TaskLaunchResult, TaskOutput, Timestamped};
use std::collections::VecDeque;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, watch};

pub struct Task {
    created_on: chrono::DateTime<chrono::Utc>,
    script: Script,
    exit_code_tx: watch::Sender<Option<Timestamped<i32>>>,
    output_tx: mpsc::Sender<Timestamped<TaskOutput>>,
    pub(crate) output_rx: mpsc::Receiver<Timestamped<TaskOutput>>,
}

impl Task {
    pub fn create(script: Script) -> Self {
        let created_on = chrono::Utc::now();
        let (exit_code_tx, _) = watch::channel(None);
        let (output_tx, output_rx) = mpsc::channel(128);
        Self {
            created_on,
            script,
            exit_code_tx,
            output_tx,
            output_rx,
        }
    }

    async fn append_stdout<T: Into<String>>(tx: mpsc::Sender<Timestamped<TaskOutput>>, line: T) {
        Self::append_output(tx, TaskOutput::Stdout(line.into())).await;
    }

    async fn append_stderr<T: Into<String>>(tx: mpsc::Sender<Timestamped<TaskOutput>>, line: T) {
        Self::append_output(tx, TaskOutput::Stderr(line.into())).await;
    }

    async fn append_output(tx: mpsc::Sender<Timestamped<TaskOutput>>, output: TaskOutput) {
        let event = Timestamped::now(output);
        if let Err(e) = tx.send(event).await {
            tracing::error!("Failed to send task output event: {e}");
        }
    }

    fn set_exit_code(tx: watch::Sender<Option<Timestamped<i32>>>, exit_code: i32) {
        let event = Timestamped::now(exit_code);
        if let Err(e) = tx.send(Some(event)) {
            tracing::error!("Failed to send task exit code: {e}");
        }
    }

    pub async fn run(
        &self,
        arguments: Vec<String>,
        attachments: Option<TempDir>,
    ) -> anyhow::Result<TaskLaunchResult> {
        let created_on = self.created_on;
        let output_tx = self.output_tx.clone();
        let script = self.script.clone();

        let mut command_with_arguments = VecDeque::from(script.command);
        let command = command_with_arguments.pop_front();
        let Some(command) = command else {
            anyhow::bail!("Script command is empty");
        };
        let mut command = tokio::process::Command::new(command);
        if !command_with_arguments.is_empty() {
            command.args(command_with_arguments);
        }
        if !arguments.is_empty() {
            command.args(arguments);
        }
        let attachments_path = attachments.as_ref().map(|a| a.path().to_path_buf());

        if let Some(ref path) = attachments_path {
            command.env("ATTACHMENTS_DIR", path);
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(username) = script.run_as {
                let user = users::get_user_by_name(&username).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "User not found")
                })?;
                command.uid(user.uid());
                command.gid(user.primary_group_id());
            };
        }

        tracing::info!("Running script: {:?}", command);

        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                Self::append_stderr(output_tx, format!("Failed to start script: {e}")).await;
                Self::set_exit_code(self.exit_code_tx.clone(), 1);
                return Err(e.into());
            }
        };

        let handler_output_tx = output_tx.clone();
        let handler_exit_code_tx = self.exit_code_tx.clone();

        let handler = tokio::spawn(async move {
            let _attachments_guard = attachments;

            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();

            let stdout_output_tx = handler_output_tx.clone();
            let stderr_output_tx = handler_output_tx.clone();

            let stdout_task = tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    Self::append_stdout(stdout_output_tx.clone(), line).await;
                }
            });

            let stderr_task = tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    Self::append_stderr(stderr_output_tx.clone(), line).await;
                }
            });

            let _ = tokio::join!(stdout_task, stderr_task);

            let exit_code = match child.wait().await {
                Ok(status) => match status.code() {
                    None => {
                        Self::append_stderr(output_tx, "Command terminated by signal").await;
                        -1
                    }
                    Some(code) => code,
                },
                Err(e) => {
                    Self::append_stderr(output_tx, format!("Command failed: {e}")).await;
                    -1
                }
            };
            Self::set_exit_code(handler_exit_code_tx, exit_code);
            exit_code
        });
        Ok(TaskLaunchResult {
            created_on,
            handler,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    fn script(command: Vec<&str>) -> Script {
        Script {
            name: "test-script".to_string(),
            run_as: None,
            command: command.into_iter().map(String::from).collect(),
        }
    }

    async fn next_output(rx: &mut mpsc::Receiver<Timestamped<TaskOutput>>) -> TaskOutput {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for a task output event")
            .expect("output channel closed unexpectedly")
            .value
    }

    #[tokio::test]
    async fn run_streams_stdout_and_resolves_the_exit_code() {
        let mut task = Task::create(script(vec!["echo", "hello from stdout"]));
        let result = task.run(vec![], None).await.unwrap();

        let event = next_output(&mut task.output_rx).await;
        let TaskOutput::Stdout(line) = event else {
            panic!("expected Stdout, got {event:?}");
        };
        assert_eq!(line, "hello from stdout");

        let exit_code = result.handler.await.unwrap();
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn run_streams_stderr() {
        let mut task = Task::create(script(vec!["bash", "-c", "echo oops >&2"]));
        let result = task.run(vec![], None).await.unwrap();

        let event = next_output(&mut task.output_rx).await;
        let TaskOutput::Stderr(line) = event else {
            panic!("expected Stderr, got {event:?}");
        };
        assert_eq!(line, "oops");

        assert_eq!(result.handler.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn run_resolves_a_non_zero_exit_code() {
        let task = Task::create(script(vec!["bash", "-c", "exit 3"]));
        let result = task.run(vec![], None).await.unwrap();
        assert_eq!(result.handler.await.unwrap(), 3);
    }

    #[tokio::test]
    async fn run_appends_extra_arguments_after_the_script_commands_own_args() {
        let mut task = Task::create(script(vec!["echo"]));
        let result = task
            .run(vec!["hello".to_string(), "world".to_string()], None)
            .await
            .unwrap();

        let event = next_output(&mut task.output_rx).await;
        let TaskOutput::Stdout(line) = event else {
            panic!("expected Stdout, got {event:?}");
        };
        assert_eq!(line, "hello world");
        assert_eq!(result.handler.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn run_exposes_the_attachments_directory_as_an_env_var() {
        let attachments = TempDir::new().unwrap();
        let expected_path = attachments.path().to_path_buf();

        let mut task = Task::create(script(vec!["bash", "-c", "echo $ATTACHMENTS_DIR"]));
        let result = task.run(vec![], Some(attachments)).await.unwrap();

        let event = next_output(&mut task.output_rx).await;
        let TaskOutput::Stdout(line) = event else {
            panic!("expected Stdout, got {event:?}");
        };
        assert_eq!(line, expected_path.display().to_string());
        assert_eq!(result.handler.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn run_rejects_an_empty_command_without_spawning_anything() {
        let task = Task::create(script(vec![]));
        let result = task.run(vec![], None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_reports_a_spawn_failure_as_both_an_error_and_a_stderr_event() {
        let mut task = Task::create(script(vec!["/nonexistent/definitely-not-a-real-binary"]));
        let result = task.run(vec![], None).await;
        assert!(result.is_err());

        let event = next_output(&mut task.output_rx).await;
        let TaskOutput::Stderr(line) = event else {
            panic!("expected Stderr, got {event:?}");
        };
        assert!(line.starts_with("Failed to start script:"));
    }

    #[tokio::test]
    async fn run_with_a_nonexistent_run_as_user_fails_before_spawning() {
        let mut script = script(vec!["echo", "should not run"]);
        script.run_as = Some("definitely-not-a-real-user-3f8a91".to_string());
        let task = Task::create(script);
        let result = task.run(vec![], None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_reports_signal_termination_as_exit_code_negative_one() {
        let mut task = Task::create(script(vec!["bash", "-c", "kill -9 $$"]));
        let result = task.run(vec![], None).await.unwrap();

        let event = next_output(&mut task.output_rx).await;
        let TaskOutput::Stderr(line) = event else {
            panic!("expected Stderr, got {event:?}");
        };
        assert_eq!(line, "Command terminated by signal");

        assert_eq!(result.handler.await.unwrap(), -1);
    }

    // Documents real, currently-existing (harmless) dead code: Task::create
    // immediately drops the watch::channel's receiver
    // (`let (exit_code_tx, _) = watch::channel(None)`), so
    // set_exit_code's `tx.send(...)` can never succeed — every task run
    // logs a spurious "Failed to send task exit code: channel closed"
    // error, which is exactly the log line seen during manual verification
    // earlier. It's inert, not a race: the real exit code is delivered via
    // the JoinHandle return value (asserted above in every other test),
    // never via this channel. This test just confirms run() completes
    // successfully regardless — the always-failing send is silently logged
    // and swallowed, not propagated as an error.
    #[tokio::test]
    async fn run_succeeds_even_though_the_internal_exit_code_watch_channel_has_no_receiver() {
        let task = Task::create(script(vec!["true"]));
        let result = task.run(vec![], None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().handler.await.unwrap(), 0);
    }
}
