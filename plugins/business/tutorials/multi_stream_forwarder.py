"""
Multi-Stream Forwarder Plugin

This plugin is designed to work with the MultiVideoStreamCv2 data capture thread.
It processes frames from multiple video streams and sends metadata to the SDK client.

The SDK client will receive:
- Metadata for all streams in the DATA field
"""

from naeural_core.business.base import CVPluginExecutor as BaseClass

__VER__ = '1.0.0'

_CONFIG = {
  **BaseClass.CONFIG,

  'ALLOW_EMPTY_INPUTS': False,
  'MAX_INPUTS_QUEUE_SIZE': 100,
  'PROCESS_DELAY': 3,  # Process every 3 seconds

  'VALIDATION_RULES': {
    **BaseClass.CONFIG['VALIDATION_RULES'],
  },
}


class MultiStreamForwarderPlugin(BaseClass):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    self._frame_counters = {}  # Track frame count per stream
    super(MultiStreamForwarderPlugin, self).__init__(**kwargs)
    return

  def startup(self):
    super().startup()
    self._frame_counters = {}
    self._total_frames_processed = 0
    self.P("Multi-Stream Forwarder Plugin started", color='g')
    self.P(f"  Process delay: {self.cfg_process_delay}s", color='g')
    self.P("  Forwarding all frames from all streams to SDK", color='g')
    return

  def _process(self):
    """
    Process frames from all active streams in the multi-video capture.

    The MultiVideoStreamCv2 DCT sends batched inputs where each input
    contains one frame per active stream. Each frame has metadata that
    identifies its source stream.

    This plugin forwards all images from all streams to the SDK client.
    """
    payload = None

    # Get all inputs from the current batch
    inputs = self.dataapi_inputs()

    if inputs is None or len(inputs) == 0:
      self.P("No inputs available", color='y')
      return payload

    self.P(f"Forwarding batch with {len(inputs)} stream(s)", color='b')

    stream_images = []

    # Process each input (one per active stream)
    for idx, inp in enumerate(inputs):
      # Debug: Show input structure (first time only)
      if idx == 0 and not hasattr(self, '_shown_input_structure'):
        self.P(f"Input structure keys: {list(inp.keys()) if isinstance(inp, dict) else 'NOT A DICT'}", color='y')
        self._shown_input_structure = True

      # Extract metadata for this specific input
      # The metadata is in the 'METADATA' key, not 'STRUCT_DATA'
      inp_metadata = inp.get('METADATA', {}) if isinstance(inp, dict) else {}

      if inp_metadata is None:
        inp_metadata = {}

      # Debug: Show metadata keys (first time only)
      if idx == 0 and not hasattr(self, '_shown_metadata_keys'):
        self.P(f"Metadata keys: {list(inp_metadata.keys()) if isinstance(inp_metadata, dict) else 'NOT A DICT'}", color='y')
        self._shown_metadata_keys = True

      # Get stream identification from metadata
      stream_name = inp_metadata.get('stream_name') or inp_metadata.get('source_name', f'stream_{idx}')
      stream_index = inp_metadata.get('stream_index', idx)
      stream_url = inp_metadata.get('stream_url') or inp_metadata.get('source_url', 'unknown')
      frame_current = inp_metadata.get('frame_current', 0)
      fps = inp_metadata.get('fps', 0)
      frame_h = inp_metadata.get('frame_h', 0)
      frame_w = inp_metadata.get('frame_w', 0)
      connected = inp_metadata.get('connected', False)

      # Initialize frame counter for this stream if not exists
      if stream_name not in self._frame_counters:
        self._frame_counters[stream_name] = 0
        self.P(f"New stream detected: {stream_name} (index: {stream_index}, url: {stream_url})", color='g')

      self._frame_counters[stream_name] += 1
      self._total_frames_processed += 1
      processed_count = self._frame_counters[stream_name]

      # Get the image for this stream
      img = inp.get('IMG') if isinstance(inp, dict) else None

      if img is None:
        self.P(f"No image for stream '{stream_name}'", color='y')
        continue

      self.P(f"  Forwarding '{stream_name}': frame {frame_current}, processed: {processed_count}, "
             f"size: {frame_h}x{frame_w}, fps: {fps}, connected: {connected}")

      # Collect ONLY metadata for this stream (no images to avoid large payloads)
      # The SDK will receive this metadata about the processed frames
      stream_images.append({
        'stream_name': stream_name,
        'stream_index': stream_index,
        'frame_index': frame_current,
        'processed_count': processed_count,
        'fps': fps,
        'resolution': f"{frame_h}x{frame_w}",
        'width': frame_w,
        'height': frame_h,
        'connected': connected,
        'url': stream_url,
        'timestamp': self.time_to_str(),
        'image_shape': list(img.shape) if img is not None else None,
      })

    # Create payload with metadata from all streams
    # Note: We're NOT including images to avoid exceeding MQTT message size limits
    # The SDK will receive this metadata in the DATA field of the payload
    payload_kwargs = {
      'data': {
        'STREAMS_PROCESSED': len(stream_images),
        'STREAM_METADATA': stream_images,  # Changed from STREAM_IMAGES since no images included
        'TOTAL_FRAMES_PROCESSED': self._total_frames_processed,
        'STREAM_COUNTERS': self._frame_counters.copy(),
        'TIMESTAMP': self.time_to_str(),
      }
    }

    payload = self._create_payload(**payload_kwargs)

    return payload
