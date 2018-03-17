
ToxAV Threads explained
=======================

Incoming:
==

```
incoming video packet:
----------------------
[Main Thread]
*enter*-->
    tox.c:tox_iterate
    Messenger.c:do_messenger
    network.c:networking_poll
    network.c:receivepacket <--- recvfrom()

    rtp.c:handle_rtp_packet
    rtp.c:handle_video_packet
    video.c:vc_queue_message ---> rb_write(*video ringbuffer*)
<--*return*


incoming audio packet:
----------------------
[Main Thread]
*enter*-->
    tox.c:tox_iterate
    Messenger.c:do_messenger
    network.c:networking_poll
    network.c:receivepacket <--- recvfrom()

    rtp.c:handle_rtp_packet
    audio.c:ac_queue_message
    audio.c:jbuf_write ---> rb_write(*audio ringbuffer*)
<--*return*


handle incoming audio+video packet:
-----------------------------------
[ToxAV Thread]
*enter*-->
    toxav.c:toxav_iterate
    audio.c:ac_iterate
    audio.c:jbuf_read <--- rb_read(*audio ring_buffer*)
    audio.c:opus_decode
        *client*:-->toxav_audio_receive_frame_cb ++block++
        *client*:<--return
    video.c:vc_iterate <--- rb_read(*video ring_buffer*)
    video.c:vpx_codec_decode ++block++
    video.c:vpx_codec_get_frame
        *client*:-->toxav_video_receive_frame_cb ++block++
        *client*:<--return
<--*return*

```


Outgoing:
==

```

outgoing video packet:
----------------------
[Some Client Thread]
*enter*-->
    toxav.c:toxav_video_send_frame
    toxac.c:vpx_codec_encode ++block++
    toxav.c:vpx_codec_get_cx_data
    rtp.c:rtp_send_data
    Messenger.c:m_send_custom_lossy_packet
    net_crypto.c:send_lossy_cryptpacket
    net_crypto.c:send_data_packet_helper
    net_crypto.c:send_data_packet
    net_crypto.c:send_packet_to ---> sendpacket()
<--*return*


outgoing audio packet:
----------------------
[Could be some other Client Thread]
*enter*-->
    toxav.c:toxav_audio_send_frame
    toxac.c:opus_encode
    rtp.c:rtp_send_data
    Messenger.c:m_send_custom_lossy_packet
    net_crypto.c:send_lossy_cryptpacket
    net_crypto.c:send_data_packet_helper
    net_crypto.c:send_data_packet
    net_crypto.c:send_packet_to ---> sendpacket()
<--*return*



```





