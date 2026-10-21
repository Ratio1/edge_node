"""Telegram background startup must drive the node's deployment observations."""
import asyncio
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from naeural_core.business.deployment_lifecycle import DeploymentLifecycle
from naeural_core.business.mixins_base.plugin_readiness_mixin import _PluginReadinessMixin
from extensions.business.mixins.telegram_mixin import _TelegramChatbotMixin


class Bot(_TelegramChatbotMixin, _PluginReadinessMixin):
  cfg_connection_pool_size = 1

  def __init__(self):
    super().__init__()
    self._init_process_finalized = True
    self.thread = SimpleNamespace(is_alive=lambda: True)
    self.ready = threading.Event()
    self.bot_build("test-token", "test-bot", lambda **kwargs: None)

  def P(self, *args, **kwargs):
    pass

  def report_deployment_status(self, status, error_code=None):
    super().report_deployment_status(status, error_code)
    if status == "ready":
      self.ready.set()


class TelegramLifecycleTests(unittest.TestCase):
  def application(self):
    app = SimpleNamespace(initialize=AsyncMock(), start=AsyncMock(), stop=AsyncMock(),
                          shutdown=AsyncMock(), add_handler=MagicMock(), add_error_handler=MagicMock(),
                          updater=SimpleNamespace(start_polling=AsyncMock(), stop=AsyncMock()))
    builder = MagicMock()
    for method in ("token", "concurrent_updates", "connection_pool_size", "rate_limiter"):
      getattr(builder, method).return_value = builder
    builder.build.return_value = app
    return app, builder

  def observation(self, bot):
    with tempfile.TemporaryDirectory() as directory:
      lifecycle = DeploymentLifecycle(str(Path(directory) / "journal.json"), "node")
      config = {"NAME": "bot", "PLUGINS": [{"SIGNATURE": "TELEGRAM_BASIC_BOT_01",
                "INSTANCES": [{"INSTANCE_ID": "bot"}]}],
                "DEEPLOY_OPERATION": {"operation_id": "op", "attempt": "deploy", "revision": 1,
                                      "coordinator": "oracle", "peers": [], "action": "start"}}
      lifecycle.admit(config, "oracle", True)
      lifecycle.attach(config, "TELEGRAM_BASIC_BOT_01", "bot", bot)
      snapshots = []
      lifecycle.publish(lambda key, value, **kwargs: snapshots.append(value) or True,
                        lambda value, **kwargs: None)
      return snapshots[-1]

  def test_background_authentication_and_polling_failures_never_report_ready(self):
    for stage in ("initialize", "polling"):
      with self.subTest(stage=stage):
        bot = Bot()
        app, builder = self.application()
        target = app.initialize if stage == "initialize" else app.updater.start_polling
        target.side_effect = ValueError("private-token-must-not-be-published")
        with patch("extensions.business.mixins.telegram_mixin.Application.builder", return_value=builder):
          bot._TelegramChatbotMixin__bot_runner()
        observed = self.observation(bot)
        self.assertEqual(observed["status"], "failed")
        self.assertEqual(observed["instances"][0]["error"]["code"], "WORKLOAD_START_FAILED")
        self.assertNotIn("private-token", str(observed))
        self.assertFalse(bot.ready.is_set())
        bot.bot_stop()  # A failed startup may already have closed its loop.

  def test_readiness_waits_for_polling_and_stop_wakes_the_bot_loop(self):
    bot = Bot()
    app, builder = self.application()
    self.assertFalse(bot.is_plugin_ready())
    async def polling_started(**kwargs):
      self.assertFalse(bot.is_plugin_ready())
    app.updater.start_polling.side_effect = polling_started
    with patch("extensions.business.mixins.telegram_mixin.Application.builder", return_value=builder):
      runner = threading.Thread(target=bot._TelegramChatbotMixin__bot_runner, daemon=True)
      bot._TelegramChatbotMixin__bot_thread = runner
      runner.start()
      stopper = None
      try:
        self.assertTrue(bot.ready.wait(2))
        self.assertEqual(self.observation(bot)["status"], "ready")
        stopper = threading.Thread(target=bot.bot_stop, daemon=True)
        stopper.start()
        stopper.join(2)
        self.assertFalse(stopper.is_alive())
        self.assertFalse(runner.is_alive())
        self.assertFalse(bot.is_plugin_ready())
        app.updater.stop.assert_awaited_once()
        app.shutdown.assert_awaited_once()
      finally:
        loop = bot._TelegramChatbotMixin__asyncio_loop
        if loop is not None and not loop.is_closed():
          loop.call_soon_threadsafe(bot._TelegramChatbotMixin__stop_event.set)
        runner.join(2)
        if stopper is not None:
          stopper.join(2)

  def test_stop_joins_runner_when_its_loop_closes_during_wakeup(self):
    bot = Bot()
    loop = asyncio.new_event_loop()
    self.addCleanup(loop.close)
    bot._TelegramChatbotMixin__asyncio_loop = loop
    bot._TelegramChatbotMixin__stop_event = asyncio.Event()
    runner = MagicMock()
    bot._TelegramChatbotMixin__bot_thread = runner
    schedule = loop.call_soon_threadsafe
    def close_then_schedule(callback):
      closing = threading.Thread(target=loop.close)
      closing.start()
      closing.join(2)
      self.assertFalse(closing.is_alive())
      return schedule(callback)
    with patch.object(loop, "call_soon_threadsafe", side_effect=close_then_schedule):
      bot.bot_stop()
    runner.join.assert_called_once()

  def test_stop_does_not_hide_scheduling_error_on_open_loop(self):
    bot = Bot()
    loop = asyncio.new_event_loop()
    self.addCleanup(loop.close)
    bot._TelegramChatbotMixin__asyncio_loop = loop
    bot._TelegramChatbotMixin__stop_event = asyncio.Event()
    with patch.object(loop, "call_soon_threadsafe", side_effect=RuntimeError("Scheduling failed")):
      with self.assertRaisesRegex(RuntimeError, "Scheduling failed"):
        bot.bot_stop()


if __name__ == "__main__":
  unittest.main()
