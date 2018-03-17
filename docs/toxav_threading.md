
ToxAV Threads explained
=======================

```
incoming video packet:
----------------------
[Main Thread]
*enter*-->
    tox.c:tox_iterate
    Messenger.c:do_messenger
    (*callback horror here*)
    rtp.c:handle_rtp_packet
    rtp.c:handle_video_packet
    video.c:vc_queue_message ---> rb_write(*video ringbuffer*)
<--*return*


incoming audio packet:
----------------------
*enter*-->
    tox.c:tox_iterate
    Messenger.c:do_messenger
    (*callback horror here*)
    rtp.c:handle_rtp_packet
    audio.c:ac_queue_message
    audio.c:jbuf_write ---> rb_write(*audio ringbuffer*)
<--*return*


audio+video packet:
-------------------
[ToxAV Thread]
*enter*-->
    toxav.c:toxav_iterate
    audio.c:ac_iterate
    audio.c:jbuf_read <--- rb_read(*audio ring_buffer*)
    audio.c:opus_decode
        *client*:-->toxav_audio_receive_frame_cb
        *client*:<--return
    video.c:vc_iterate <--- rb_read(*video ring_buffer*)
    video.c:vpx_codec_decode
    video.c:vpx_codec_get_frame
        *client*:-->toxav_video_receive_frame_cb
        *client*:<--return
<--*return*
```


