# Samsung VD-family OCF devices: what a server-authenticated channel reaches

This is a compatibility and inventory note, not an onboarding or
ownership-transfer guide. It records the sanitized facts confirmed against two
Samsung VD-family (Visual Display) devices — a soundbar and a television —
using `SamsungServerProfile` / `ServerCertificateAuth` with the
`SamsungServerRole.VD_DEVICE` role.

Every row in the README's tested-combinations table is a home-appliance-role
device (`OU=OCF HA Device`).

The scope is deliberately narrow. A server-authenticated channel proves the
*device's* identity to the client. It does not prove the client's identity to
the device, and it does not grant authorization. Endpoint reachability, DTLS
authentication, resource authorization, and OCF ownership remain four separate
states, and a result at one layer is not proof that the next is usable.

## Hardware validated

| Field | Soundbar | Television |
|---|---|---|
| `oic.wk.d` `rt` | `oic.d.networkaudio` | `oic.d.tv` |
| `mnmo` | `HW-S61B` | `UE50TU7172UXXH` |
| `mnfv` | `HW-S61BWWB-1010.0` | `T-KTSU2DEUC-2740.1` |
| `vid` | `VD-NetworkAudio-002S` | `VD-STV_2018_K` |
| `mnos` / `mnpv` | Tizen 6.5 | Tizen 5.5 |
| `/oic/res` links | 64 | 67 |

Both are retail units on stock firmware, paired to SmartThings, and were read
without being reset, re-claimed, or otherwise modified.

## What the server-authenticated channel confirms

On both devices:

- the device presents a leaf carrying the exact subject role
  `C=KR, O=Samsung Electronics, OU=OCF VD Device`, with the chain verifying
  to the OCF root bundled with this library, certificate-chain verification
  left enabled and no cipher-list widening; and
- unprotected resources answer normally over the resulting session.

Two negative controls ran against the soundbar and both refused:

- a pinned certificate UUID that does not match the device's leaf; and
- the home-appliance role (`OU=OCF HA Device`) selected against this VD leaf.

The profile therefore discriminates on the fields it claims to, rather than
accepting whatever reaches it.

## What it does not confirm

- **No authorized client credential.** Protected resources refuse the
  server-only channel; `/sec/networkaudio/deviceinfo` on the soundbar and
  `/sec/tv/deviceinfo` on the television answer `4.01 Unauthorized`. That is
  the boundary of this channel, not a gap in the setup.
- **No ownership transfer.** Nothing here performs OTM or writes
  `/oic/sec/*`.
- **No movement on [#16](https://github.com/QuiteYellow/SmartThings-Local/issues/16)
  or [#20](https://github.com/QuiteYellow/SmartThings-Local/issues/20).**
  Those issues turn on getting an authorized client credential onto an
  already-owned device, which remains unsolved. A reader should not conclude
  otherwise from anything in this note.
- **No bridge support.** There is no descriptor for either device class, and
  the entity/polling machinery described in the README does not apply to them.

## Public security state

Read from the unprotected security resources. Both devices are owned and
operational:

| Field | Soundbar | Television |
|---|---|---|
| `doxm.oxms` | `1, 2, 65282` (`0xFF02`) | `1, 2, 65282` (`0xFF02`) |
| `doxm.oxmsel` | `2` | `1` |
| `doxm.sct` | `1` | `1` |
| `doxm.owned` | `true` | `true` |
| `pstat.isop` | `true` | `true` |
| `pstat.cm` / `tm` | `0` / `0` | `0` / `0` |
| `pstat.om` / `sm` | `4` / `4` | `4` / `4` |

Both advertise the standard manufacturer-certificate OTM `2` alongside
Samsung's `0xFF02`, the same pair the newer OCF-PKI laundry profile advertises
(see [`ocf-pki-laundry.md`](ocf-pki-laundry.md)). Device, owner, and
resource-owner UUIDs are sensitive identifiers, are not needed to reproduce any
of this, and are not reproduced here.

### Remarks

Recorded so the next reader does not have to rediscover them, and explicitly
not validated except where noted:

- Removing a device from SmartThings returns it to the unowned OCF state —
  the manufacturer-OTM window `ocf-pki-laundry.md` describes. It may
  therefore be possible to claim the device directly using IoTivity-Lite.
- Each device gates that path behind a physical user confirmation — a
  particular button press on the soundbar, a PIN shown on the television's
  screen.
- Obtaining the owner credential during SmartThings' own ownership-transfer
  flow is the other known route: probably the more difficult approach, and
  confirmed to be working.
- the leaf's `TbsCertificate::signature_alg` is one `cryptography` refuses to
  parse. This is the real-hardware version of the synthetic DER fixture that
  motivated removing the `to_cryptography()` step: on the current parser the
  handshake completes, and on the previous one it would not have.

## Advertised resource directory

Both tables are the device's own `/oic/res` link list, reduced to the fields
that are safe to publish: `href`, `rt`, `if`, the `bm` bitmask (`3` =
discoverable + observable, `1` = discoverable only), and whether the link is
advertised as secure. The `port` and `x.org.iotivity.tls` values are omitted
because they are assigned per boot and are not stable; rediscover the secure
endpoint rather than hardcoding one. On both units the secure UDP endpoint
is the `port` value on the `sec: yes` links; the `x.org.iotivity.tls` value
advertised alongside it did not answer DTLS. Interface names are shortened
from `oic.if.baseline` to `baseline` and so on.

A `sec: yes` link means the device advertises it on the DTLS endpoint. It says
nothing about whether a given credential is authorized to read it — on the
server-authenticated channel most of these still answer `4.01`.

### Soundbar — `VD-NetworkAudio-002S`, 64 links

| href | rt | if | bm | sec |
|---|---|---|---|---|
| `/CoapCloudConfResURI` | `oic.r.coapcloudconf` | `baseline` | 3 | yes |
| `/DevConfResURI` | `oic.r.devconf` | `baseline` | 3 | yes |
| `/EasySetupResURI` | `oic.r.easysetup, oic.wk.col` | `baseline, ll, b` | 3 | yes |
| `/WiFiConfResURI` | `oic.r.wificonf` | `baseline` | 3 | yes |
| `/capability/audioTrackData/main/0` | `x.com.st.audiotrackdata` | `baseline, s` | 3 | yes |
| `/capability/mediaPlayback/main/0` | `x.com.st.mediaplayer` | `baseline, a, s` | 3 | yes |
| `/capability/mediaPlaybackRepeat/main/0` | `x.com.st.mediarepeat` | `baseline, a, s` | 3 | yes |
| `/capability/mediaPlaybackShuffle/main/0` | `x.com.st.mediashuffle` | `baseline, a, s` | 3 | yes |
| `/capability/mediaTrackControl/main/0` | `x.com.st.mediatrackcontrol` | `baseline, a, s` | 3 | yes |
| `/oic/d` | `oic.wk.d, oic.d.networkaudio` | `baseline, r` | 1 | no |
| `/oic/p` | `oic.wk.p` | `baseline, r` | 1 | no |
| `/oic/sec/doxm` | `oic.r.doxm` | `baseline` | 1 | yes |
| `/oic/sec/pstat` | `oic.r.pstat` | `baseline` | 1 | yes |
| `/sec/accesspointlist` | `x.com.samsung.accesspointlist` | `baseline, s` | 1 | no |
| `/sec/alexa/aisettingpopup` | `x.com.samsung.alexa.aisettingpopup` | `baseline, rw` | 3 | yes |
| `/sec/alexa/avsDeviceInfo` | `x.com.samsung.alexa.avsDeviceInfo` | `baseline, a` | 3 | yes |
| `/sec/alexa/avsSignIn` | `x.com.samsung.alexa.avsSignIn` | `baseline, a` | 3 | yes |
| `/sec/alexa/avsSignInStatus` | `x.com.samsung.alexa.avsSignInStatus` | `baseline, a` | 3 | yes |
| `/sec/alexa/avsSubMode` | `x.com.samsung.alexa.avsSubMode` | `baseline, rw` | 3 | yes |
| `/sec/alexa/listlocale` | `x.com.samsung.alexa.localelist` | `baseline, a` | 3 | yes |
| `/sec/alexa/locale` | `x.com.samsung.alexa.locale` | `baseline, rw` | 3 | yes |
| `/sec/alexa/userprofile` | `x.com.samsung.alexa.userprofile` | `baseline, a` | 3 | yes |
| `/sec/contentPanel/support` | `x.com.samsung.contentpanel.support` | `baseline, a` | 3 | yes |
| `/sec/languagelist` | `x.com.samsung.languagelist` | `baseline, s` | 1 | no |
| `/sec/mde` | `x.com.samsung.mde` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/activeVoiceAmplifier` | `x.com.samsung.networkaudio.activeVoiceAmplifier` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/advancedaudio` | `x.com.samsung.networkaudio.advancedaudio` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/audio` | `oic.r.audio` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/audioPrompt` | `x.com.samsung.networkaudio.audioPrompt` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/audiosync` | `x.com.samsung.networkaudio.audiosync` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/autoPowerDown` | `x.com.samsung.networkaudio.autoPowerDown` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/autoUpdate` | `x.com.samsung.networkaudio.autoUpdate` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/autoeq` | `x.com.samsung.networkaudio.autoeq` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/btPairingMode` | `x.com.samsung.networkaudio.btPairingMode` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/channelVolume` | `x.com.samsung.networkaudio.channelVolume` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/currentEQMode` | `x.com.samsung.networkaudio.currentEQMode` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/deviceinfo` | `x.com.samsung.networkaudio.deviceinfo` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/eq` | `x.com.samsung.networkaudio.eq` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/feature` | `x.com.samsung.networkaudio.feature` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/googlesupport` | `x.com.samsung.networkaudio.googlesupport` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/installationType` | `x.com.samsung.networkaudio.installationType` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/lastConnections` | `x.com.samsung.networkaudio.lastConnections` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/mic` | `x.com.samsung.networkaudio.mic` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/mode` | `oic.r.mode` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/musicinfo` | `x.com.samsung.networkaudio.musicinfo` | `baseline, s` | 3 | yes |
| `/sec/networkaudio/networkInfo` | `x.com.samsung.networkaudio.networkInfo` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/passThrough` | `x.com.samsung.networkaudio.passThrough` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/playback` | `x.com.samsung.networkaudio.playback` | `baseline, a, s` | 3 | yes |
| `/sec/networkaudio/soundFrom` | `x.com.samsung.networkaudio.soundFrom` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/soundmode` | `x.com.samsung.networkaudio.soundmode` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/spacefitSound` | `x.com.samsung.networkaudio.spacefitSound` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/speakerStatus` | `x.com.samsung.networkaudio.speakerStatus` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/surroundspeaker` | `x.com.samsung.networkaudio.surroundspeaker` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/swUpdate` | `x.com.samsung.networkaudio.swUpdate` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/switch/binary` | `oic.r.switch.binary` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/symphony` | `x.com.samsung.networkaudio.symphony` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/tone` | `x.com.samsung.networkaudio.tone` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/vasupport` | `x.com.samsung.networkaudio.vasupport` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/versionInfo` | `x.com.samsung.networkaudio.versionInfo` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/vfd` | `x.com.samsung.networkaudio.vfd` | `baseline, a` | 3 | yes |
| `/sec/networkaudio/volumeUpDown` | `x.com.samsung.networkaudio.volumeUpDown` | `baseline, rw` | 3 | yes |
| `/sec/networkaudio/woofer` | `x.com.samsung.networkaudio.woofer` | `baseline, a` | 3 | yes |
| `/sec/provisioninginfo` | `x.com.samsung.provisioninginfo` | `baseline, a` | 1 | no |
| `/x.com.samsung/notification/receiver` | `x.com.samsung.audionotification` | `baseline, a` | 3 | yes |

### Television — `VD-STV_2018_K`, 67 links

| href | rt | if | bm | sec |
|---|---|---|---|---|
| `/CoapCloudConfResURI` | `oic.r.coapcloudconf` | `baseline` | 3 | yes |
| `/DevConfResURI` | `oic.r.devconf` | `baseline` | 3 | yes |
| `/EasySetupResURI` | `oic.r.easysetup, oic.wk.col` | `baseline, ll, b` | 3 | yes |
| `/WiFiConfResURI` | `oic.r.wificonf` | `baseline` | 3 | yes |
| `/autoreconnect/ap` | `x.com.samsung.autoreconnect.ap` | `baseline, a` | 1 | yes |
| `/capability/audioTrackData/main/0` | `x.com.st.audiotrackdata` | `baseline, a` | 3 | yes |
| `/capability/audioVolume/main/0` | `x.com.st.audiovolume` | `baseline, a` | 3 | yes |
| `/capability/custom.ocfResourceVersion/main/0` | `x.com.st.r.custom.ocfResourceVersion` | `baseline, s` | 3 | yes |
| `/capability/mediaPlayback/main/0` | `x.com.st.mediaplayer` | `baseline, a` | 3 | yes |
| `/capability/mediaPlaybackRepeat/main/0` | `x.com.st.mediarepeat` | `baseline, a` | 3 | yes |
| `/capability/mediaPlaybackShuffle/main/0` | `x.com.st.mediashuffle` | `baseline, a` | 3 | yes |
| `/capability/mediaTrackControl/main/0` | `x.com.st.mediatrackcontrol` | `baseline, a` | 3 | yes |
| `/capability/sec.diagnosticsInformation/main/0` | `x.com.st.r.sec.diagnosticsInformation` | `baseline, s` | 3 | yes |
| `/capability/videoMetaData/main/0` | `x.com.st.videometadata` | `baseline, a` | 3 | yes |
| `/content/continuity/renderer` | `x.com.samsung.contents.renderer.continuity` | `baseline, a` | 3 | yes |
| `/content/renderer` | `x.com.samsung.contents.renderer, x.com.samsung.contents.renderer.image, x.com.samsung.contents.renderer.video, x.com.samsung.contents.renderer.live_cast` | `baseline, a` | 1 | yes |
| `/devicelog/command` | `x.com.samsung.devicelog.command` | `baseline, a` | 1 | no |
| `/devicelog/connectioninfo` | `x.com.samsung.devicelog` | `baseline, a` | 1 | no |
| `/devicelog/dump` | `x.com.samsung.devicelog.dump` | `baseline, a` | 1 | no |
| `/oic/d` | `oic.wk.d, oic.d.tv` | `baseline, r` | 1 | no |
| `/oic/p` | `oic.wk.p` | `baseline, r` | 1 | no |
| `/oic/sec/doxm` | `oic.r.doxm` | `baseline` | 1 | yes |
| `/oic/sec/pstat` | `oic.r.pstat` | `baseline` | 1 | yes |
| `/sec/accesspointlist` | `x.com.samsung.accesspointlist` | `baseline, s` | 1 | no |
| `/sec/cast/remote/control` | `x.com.samsung.cast.remote.control` | `baseline, a` | 3 | yes |
| `/sec/cast/remote/item/status` | `x.com.samsung.cast.remote.item.status` | `baseline, a` | 3 | yes |
| `/sec/cast/remote/session` | `x.com.samsung.cast.remote.session` | `baseline, a` | 3 | yes |
| `/sec/contentPanel/info` | `x.com.samsung.contentpanel.info` | `baseline, a` | 3 | yes |
| `/sec/contentPanel/support` | `x.com.samsung.contentpanel.support` | `baseline, a` | 3 | yes |
| `/sec/languagelist` | `x.com.samsung.languagelist` | `baseline, s` | 1 | no |
| `/sec/mde` | `x.com.samsung.mde` | `baseline, a` | 3 | yes |
| `/sec/mde/mirroring` | `x.com.samsung.mde.mirroring` | `baseline, a` | 1 | yes |
| `/sec/provisioninginfo` | `x.com.samsung.provisioninginfo` | `baseline, a` | 1 | no |
| `/sec/tv/appdata/ambient-ua-agent` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/ambientapp` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/aodBrowser` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/contentsapp` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/lighthomeapp` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/mledmultiview` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/mobilebff` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/oobe` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/remote-server` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/ssoservice` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/appdata/ub` | `x.com.samsung.tv.appdata` | `baseline, a` | 3 | yes |
| `/sec/tv/audio` | `oic.r.audio, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |
| `/sec/tv/category/tv` | `x.com.samsung.tv.category` | `baseline, s` | 1 | yes |
| `/sec/tv/channel` | `x.com.samsung.tv.channel, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |
| `/sec/tv/contentinfo` | `x.com.samsung.tv.contentinfo` | `baseline, a` | 3 | yes |
| `/sec/tv/contentinfo/thumbnail` | `x.com.samsung.tv.contentinfo.thumbnail` | `baseline, r` | 1 | yes |
| `/sec/tv/deviceinfo` | `x.com.samsung.tv.deviceinfo` | `baseline, r` | 1 | yes |
| `/sec/tv/ime` | `x.com.samsung.tv.ime` | `baseline, a` | 3 | yes |
| `/sec/tv/inputsource` | `x.com.samsung.tv.mode, x.com.samsung.tv.errorcode` | `baseline, a` | 3 | yes |
| `/sec/tv/launchapp` | `x.com.samsung.tv.launchapp, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |
| `/sec/tv/launchnativeapp` | `x.com.samsung.tv.launchnativeapp, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |
| `/sec/tv/mediaInput` | `oic.r.media.input` | `baseline, a` | 1 | yes |
| `/sec/tv/mode/picture` | `x.com.samsung.tv.mode, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |
| `/sec/tv/mode/sound` | `x.com.samsung.tv.mode, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |
| `/sec/tv/msoinfo` | `x.com.samsung.tv.msoinfo` | `baseline, s` | 3 | yes |
| `/sec/tv/onsupport` | `x.com.samsung.tv.onsupport` | `baseline, s` | 3 | yes |
| `/sec/tv/optioncontrol` | `x.com.samsung.tv.optioncontrol, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |
| `/sec/tv/remotecontrol` | `x.com.samsung.tv.remotecontrol` | `baseline, a` | 1 | yes |
| `/sec/tv/searchall` | `x.com.samsung.tv.searchall` | `baseline, a` | 1 | yes |
| `/sec/tv/searchonweb` | `x.com.samsung.tv.searchonweb` | `baseline, a` | 1 | yes |
| `/sec/tv/showmenu` | `x.com.samsung.tv.showmenu` | `baseline, a` | 1 | yes |
| `/sec/tv/switch/binary` | `oic.r.switch.binary` | `baseline, a` | 3 | yes |
| `/sec/tv/tapview` | `x.com.samsung.tv.tapview` | `baseline, s` | 1 | yes |
| `/sec/tv/uicontrol` | `x.com.samsung.tv.uicontrol, x.com.samsung.tv.errorcode` | `baseline, a` | 1 | yes |

## Safe evidence for another VD device report

The same discipline as the laundry note. Useful public evidence is limited to:

- retail model and software version, without a serial number;
- the `vid` and the `oic.wk.d` resource type;
- the leaf's subject role, without its fingerprint or certificate UUID;
- sanitized `/oic/res` link shapes as above; and
- redacted `/oic/sec/doxm` and `/oic/sec/pstat` field values.

Do not post device, owner, or resource-owner UUIDs, certificate UUIDs or
fingerprints, MAC addresses, SSIDs or access-point scans, account identifiers,
network addresses, dynamic secure-endpoint ports, packet captures, or raw
exception traces. The raw capture this note was written from contains most of
those and is not part of the repository.
