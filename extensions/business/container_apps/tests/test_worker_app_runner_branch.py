import shlex
import unittest

from extensions.business.container_apps.tests import support  # noqa: F401
from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin


def make_worker_app_runner():
  plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
  plugin.logged_messages = []

  def _log(*args, **kwargs):
    if args:
      plugin.logged_messages.append(str(args[0]))
    return

  plugin.P = _log
  plugin.Pd = _log
  plugin.cfg_car_verbose = 10
  plugin.cfg_setup_repo = True
  plugin.cfg_vcs_data = {}
  plugin._build_commands = ["npm install", "npm start"]
  plugin._repo_configured = True
  plugin._repo_owner = "ratio1"
  plugin._repo_name = "demo"
  plugin.branch = "main"
  plugin.repo_url = "https://github.com/ratio1/demo.git"
  plugin._ensure_repo_state = lambda *args, **kwargs: None
  return plugin


class WorkerAppRunnerBranchTests(unittest.TestCase):

  def test_collect_exec_commands_clones_configured_branch(self):
    plugin = make_worker_app_runner()
    plugin.branch = "feature/api"

    commands = plugin._collect_exec_commands()

    self.assertIn(
      "git clone --branch feature/api --single-branch https://github.com/ratio1/demo.git /app",
      commands,
    )

  def test_build_git_clone_command_quotes_shell_inputs(self):
    plugin = make_worker_app_runner()
    plugin.branch = "feature/user's-fix"
    plugin.repo_url = "https://token'secret@github.com/ratio1/demo.git"

    command = plugin._build_git_clone_command("/tmp/worker app")

    self.assertEqual(
      command,
      "git clone --branch {} --single-branch {} {}".format(
        shlex.quote(plugin.branch),
        shlex.quote(plugin.repo_url),
        shlex.quote("/tmp/worker app"),
      ),
    )

  def test_build_git_clone_command_allows_unresolved_branch(self):
    plugin = make_worker_app_runner()
    plugin.branch = None

    command = plugin._build_git_clone_command("/app")

    self.assertEqual(
      command,
      "git clone https://github.com/ratio1/demo.git /app",
    )

  def test_set_default_branch_uses_github_default_when_branch_missing(self):
    plugin = make_worker_app_runner()
    plugin.branch = None
    plugin.cfg_vcs_data = {}

    def fake_get_latest_commit(return_data=False):
      self.assertTrue(return_data)
      return None, {"default_branch": "develop"}

    plugin._get_latest_commit = fake_get_latest_commit

    plugin._set_default_branch()

    self.assertEqual(plugin.branch, "develop")

  def test_set_default_branch_treats_blank_config_branch_as_missing(self):
    plugin = make_worker_app_runner()
    plugin.branch = None
    plugin.cfg_vcs_data = {"BRANCH": "   "}

    def fake_get_latest_commit(return_data=False):
      self.assertTrue(return_data)
      return None, {"default_branch": "release"}

    plugin._get_latest_commit = fake_get_latest_commit

    plugin._set_default_branch()

    self.assertEqual(plugin.branch, "release")

  def test_set_default_branch_falls_back_to_main_when_default_unavailable(self):
    plugin = make_worker_app_runner()
    plugin.branch = None
    plugin.cfg_vcs_data = {}
    plugin._get_latest_commit = lambda return_data=False: (None, None)

    plugin._set_default_branch()

    self.assertEqual(plugin.branch, "main")

  def test_set_default_branch_keeps_explicit_branch(self):
    plugin = make_worker_app_runner()
    plugin.branch = None
    plugin.cfg_vcs_data = {"BRANCH": " release/2026-05 "}
    plugin._get_latest_commit = lambda *args, **kwargs: self.fail(
      "_get_latest_commit should not be called for an explicit branch"
    )

    plugin._set_default_branch()

    self.assertEqual(plugin.branch, "release/2026-05")


if __name__ == "__main__":
  unittest.main()
