import bundleManager from '@ohos.bundle.bundleManager';
import faultLogger from '@ohos.faultLogger';
import hilog from '@ohos.hilog';

const DOMAIN = 0x0001;
const TAG = 'Index';

@Entry
@Component
struct Index {
  @State statusText: string = 'Starting system-service probes...';
  @State responseText: string = '';

  aboutToAppear(): void {
    hilog.info(DOMAIN, TAG, 'Index aboutToAppear - system-service probes');
    this.runSystemServiceProbes();
  }

  async runSystemServiceProbes(): Promise<void> {
    await this.probeBundleManager();
    await this.probeFaultLogger();
  }

  /** Read-only call to the Bundle Manager for the current HAP. */
  async probeBundleManager(): Promise<void> {
    this.statusText = 'Querying Bundle Manager...';
    hilog.info(DOMAIN, TAG, 'BundleManager probe started');
    try {
      const info = await bundleManager.getBundleInfoForSelf(
        bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT
      );
      const summary = `bundle=${info.name}; version=${info.versionName}(${info.versionCode})`;
      this.responseText = summary;
      hilog.info(DOMAIN, TAG, `BundleManager probe success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText = `BundleManager ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `BundleManager probe failed: ${message}`);
    }
  }

  /**
   * Read-only call to the public FaultLogger API. The system service queries
   * fault records belonging to this HAP; it does not create a crash or send a
   * raw faultloggerd socket request.
   */
  async probeFaultLogger(): Promise<void> {
    this.statusText = 'Querying FaultLogger...';
    hilog.info(DOMAIN, TAG, 'FaultLogger probe started');
    try {
      const records = await faultLogger.querySelfFaultLog(faultLogger.FaultType.NO_SPECIFIC);
      const summary = `faultRecords=${records.length}`;
      this.statusText = 'System-service probes complete';
      this.responseText += `; FaultLogger OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `FaultLogger probe success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.statusText = 'FaultLogger query failed';
      this.responseText += `; FaultLogger ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `FaultLogger probe failed: ${message}`);
    }
  }

  private errorMessage(err: Object): string {
    if (err instanceof Error) {
      return err.message;
    }
    return String(err);
  }

  build() {
    Column() {
      Text('VulnFounder HAP — system-service probe')
        .fontSize(22)
        .fontWeight(FontWeight.Bold)
        .margin({ top: 25, bottom: 10 })

      Text('Bundle Manager + FaultLogger')
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
