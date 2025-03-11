"""
telegram_basic_bot_01.py
------------------------

This file contains the implementation of a basic Telegram bot plugin for the Ratio1 Edge Node ecosystem.
It extends the functionality of the base plugin executor and integrates with the 
Telegram API to handle messages and process responses.

The plugin instance receives two main handlers as base64 encoded python code:
1. `MESSAGE_HANDLER`: A custom message handler that processes incoming messages.
2. `PROCESSING_HANDLER`: A custom processing handler that runs in a loop to handle bot operations.


"""
from naeural_core.business.base import BasePluginExecutor as BasePlugin
from extensions.business.mixins.telegram_mixin import _TelegramChatbotMixin

_CONFIG = {
  **BasePlugin.CONFIG,
  
  "PROCESS_DELAY"           : 1,
  "ALLOW_EMPTY_INPUTS"      : True,
  
  "SEND_STATUS_EACH"        : 60,
  
  "TELEGRAM_BOT_NAME"       : None,
  "TELEGRAM_BOT_TOKEN"      : None,
  
  "MESSAGE_HANDLER"         : None,
  "MESSAGE_HANDLER_ARGS"    : [],
  "MESSAGE_HANDLER_NAME"    : None,
  
  "PROCESSING_HANDLER"       : None,
  "PROCESSING_HANDLER_ARGS"  : [],
  

  'VALIDATION_RULES' : {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },  
}

class TelegramBasicBot01Plugin(
  _TelegramChatbotMixin,
  BasePlugin,
  ):  
  CONFIG = _CONFIG
  
  def __create_custom_reply_executor(self, str_base64_code, lst_arguments):
    self.P(f"Preparing custom reply executor with arguments: {lst_arguments}...")
    #
    self.__custom_handler, errors, warnings = self._get_method_from_custom_code(
      str_b64code=str_base64_code,
      self_var='plugin',
      method_arguments=['plugin'] + lst_arguments,

      debug=True,
    )
    #
    if errors:
      self.P(f"Errors found in custom reply executor: {errors}")
    if warnings:
      self.P(f"Warnings found in custom reply executor: {warnings}")
    if self.__custom_handler is None:
      self.P("Custom reply executor could not be created", color='r')
    else:
      self.P(f"Custom reply executor created: {self.__custom_handler}")
    return
  
  
  def on_init(self):
    self.__token = self.cfg_telegram_bot_token
    self.__bot_name = self.cfg_telegram_bot_name
        
    self.__last_status_check = 0
    self.__create_custom_reply_executor(
      str_base64_code=self.cfg_message_handler,
      lst_arguments=self.cfg_message_handler_args,
    )
    
    self._create_tbot_loop_processing_handler(
      str_base64_code=self.cfg_processing_handler,
      lst_arguments=self.cfg_processing_handler_args,
    )
    
    if self.__custom_handler is not None:
      self.P("Building and running the Telegram bot...")  
      self.bot_build(
        token=self.__token,
        bot_name=self.__bot_name,
        message_handler=self.bot_msg_handler,
        run_threaded=True,
      )      
      self.bot_run()
      self.__failed = False
    else:
      self.P("Custom reply executor could not be created, bot will not run", color='r')
      self.__failed = True
      raise ValueError("Custom reply executor could not be created")
    return


  def bot_msg_handler(self, message, user, **kwargs):
    result = self.__custom_handler(plugin=self, message=message, user=user)
    return result


  def process(self):
    payload = None
    if (self.time() - self.__last_status_check) > self.cfg_send_status_each:
      self.__last_status_check = self.time()
      if not self.__failed:
        self.bot_dump_stats()
    self.maybe_process_tbot_loop()    
    return payload