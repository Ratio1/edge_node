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
    
  
  def on_init(self):
    self.__token = self.cfg_telegram_bot_token
    self.__bot_name = self.cfg_telegram_bot_name
        
    self.__last_status_check = 0

    self.P(f"Preparing custom reply executor with arguments: {self.cfg_message_handler_args}...")        
    self._reply_handler = self._create_custom_handler(
      str_base64_code=self.cfg_message_handler,
      lst_arguments=self.cfg_message_handler_args,
    )
    
    if self.cfg_processing_handler is not None:
      self.P(f"Preparing custom loop process handler...")
      self._process_handler = self._create_custom_handler(
        str_base64_code=self.cfg_processing_handler,
        lst_arguments=self.cfg_processing_handler_args,
      )
    else:
      self._process_handler = None
    
    
    if self._reply_handler is not None:
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


  def on_close(self):
    self.P("Initiating bot shutdown procedure...")
    self.bot_stop()
    return  


  def bot_msg_handler(self, message, user, **kwargs):
    result = self._reply_handler(plugin=self, message=message, user=user)
    return result


  def maybe_process_and_auto_messages(self):
    if getattr(self, "_process_handler", None) is not None:
      result = self._process_handler(plugin=self)
      if result is not None:
        if isinstance(result, dict):
          self.add_payload_by_fields(**result)
        else:
          self.add_payload_by_fields(result=result)
      # endif result is not None
    # endif _tbot_loop_processing_handler is not None
    return  


  def process(self):
    payload = None
    if (self.time() - self.__last_status_check) > self.cfg_send_status_each:
      self.__last_status_check = self.time()
      if not self.__failed:
        self.bot_dump_stats()
    self.maybe_process_and_auto_messages()    
    return payload