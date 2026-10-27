import bundleManager from '@ohos.bundle.bundleManager';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import osAccount from '@ohos.account.osAccount';
import distributedDeviceManager from '@ohos.distributedDeviceManager';
import distributedKVStore from '@ohos.data.distributedKVStore';
import formProvider from '@ohos.app.form.formProvider';
import faultLogger from '@ohos.faultLogger';
import image from '@ohos.multimedia.image';
import media from '@ohos.multimedia.media';
import fs from '@ohos.file.fs';
import hilog from '@ohos.hilog';
import { BusinessError } from '@ohos.base';

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
    await this.probeAccessToken();
    await this.probeOsAccount();
    await this.probeDistributedDeviceManager();
    await this.probeOwnForms();
    await this.probeOwnKvStore();
    await this.probeBundledImage();
    await this.probeOwnMediaFile();
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

  /** Read-only permission-state query for this HAP; it never requests permission. */
  async probeAccessToken(): Promise<void> {
    this.statusText = 'Querying AccessToken for this HAP...';
    hilog.info(DOMAIN, TAG, 'AccessToken self-permission probe started');
    try {
      const manager = abilityAccessCtrl.createAtManager();
      const state = manager.getSelfPermissionStatus('ohos.permission.INTERNET');
      const summary = `self INTERNET status=${state}`;
      this.responseText += `; AccessToken OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `AccessToken self-permission probe success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText += `; AccessToken ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `AccessToken self-permission probe failed: ${message}`);
    }
  }

  /** Read-only query for the OS account that owns this HAP process. */
  async probeOsAccount(): Promise<void> {
    this.statusText = 'Querying this HAP OS account...';
    hilog.info(DOMAIN, TAG, 'OS Account self-query started');
    try {
      const manager = osAccount.getAccountManager();
      const localId = await manager.getOsAccountLocalId();
      const summary = `self localId=${localId}`;
      this.responseText += `; OS Account OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `OS Account self-query success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText += `; OS Account ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `OS Account self-query failed: ${message}`);
    }
  }

  /** Read-only local-device query without declaring the distributed-data permission. */
  async probeDistributedDeviceManager(): Promise<void> {
    this.statusText = 'Checking distributed-device API access...';
    hilog.info(DOMAIN, TAG, 'Distributed Device Manager permission-boundary probe started');
    let manager: distributedDeviceManager.DeviceManager | undefined;
    try {
      manager = distributedDeviceManager.createDeviceManager('com.security.research.trigger');
      const name = manager.getLocalDeviceName();
      const summary = `local device name query succeeded; value length=${name.length}`;
      this.responseText += `; Distributed Device Manager OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `Distributed Device Manager probe success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText += `; Distributed Device Manager denied/unavailable: ${message}`;
      hilog.info(DOMAIN, TAG, `Distributed Device Manager probe blocked as expected or unavailable: ${message}`);
    } finally {
      if (manager) {
        try { distributedDeviceManager.releaseDeviceManager(manager); } catch (_) {}
      }
    }
  }

  /** Read-only Form Manager query scoped to this HAP; it does not create a widget. */
  async probeOwnForms(): Promise<void> {
    this.statusText = 'Querying this HAP own forms...';
    hilog.info(DOMAIN, TAG, 'Form Manager own-form query started');
    try {
      const forms = await formProvider.getFormsInfo();
      const summary = `own form metadata count=${forms.length}`;
      this.responseText += `; Form Manager OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `Form Manager own-form query success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText += `; Form Manager ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `Form Manager own-form query failed: ${message}`);
    }
  }

  /** Write/read/delete one unique value in this HAP's private, non-synced KV store. */
  async probeOwnKvStore(): Promise<void> {
    this.statusText = 'Checking this HAP private KV store...';
    hilog.info(DOMAIN, TAG, 'DistributedData self-store probe started');
    const bundleName = 'com.security.research.trigger';
    const storeId = 'VF_SMOKE_20261015';
    const key = 'probe_key';
    const value = 'self-only-smoke-value';
    const options: distributedKVStore.Options = {
      createIfMissing: true,
      encrypt: false,
      backup: false,
      autoSync: false,
      kvStoreType: distributedKVStore.KVStoreType.SINGLE_VERSION,
      securityLevel: distributedKVStore.SecurityLevel.S1
    };
    let manager: distributedKVStore.KVManager | undefined;
    let opened = false;
    try {
      manager = distributedKVStore.createKVManager({
        context: getContext(this),
        bundleName
      });
      const store = await manager.getKVStore<distributedKVStore.SingleKVStore>(storeId, options);
      opened = true;
      await store.put(key, value);
      const observed = await store.get(key);
      await store.delete(key);
      await manager.closeKVStore(bundleName, storeId, options);
      opened = false;
      await manager.deleteKVStore(bundleName, storeId, options);
      const summary = `self KV round-trip=${observed === value}; temporary store deleted`;
      this.responseText += `; DistributedData OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `DistributedData self-store probe success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText += `; DistributedData ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `DistributedData self-store probe failed: ${message}`);
      if (manager && opened) {
        try { await manager.closeKVStore(bundleName, storeId, options); } catch (_) {}
      }
      if (manager) {
        try { await manager.deleteKVStore(bundleName, storeId, options); } catch (_) {}
      }
    }
  }

  /** Decode only a tiny PNG byte array embedded in this HAP; no device files are read. */
  async probeBundledImage(): Promise<void> {
    this.statusText = 'Decoding a bundled 1×1 image...';
    hilog.info(DOMAIN, TAG, 'Image Framework self-contained decode probe started');
    const pngBytes: Uint8Array = new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
      0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
      0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41,
      0x54, 0x78, 0xda, 0x63, 0xfc, 0xff, 0x9f, 0xa1,
      0x1e, 0x00, 0x07, 0x82, 0x02, 0x7f, 0x3d, 0xc8,
      0x48, 0xef, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
      0x4e, 0x44, 0xae, 0x42, 0x60, 0x82
    ]);
    let source: image.ImageSource | undefined;
    let pixelMap: image.PixelMap | undefined;
    try {
      source = image.createImageSource(pngBytes.buffer);
      if (!source) {
        throw new Error('ImageSource creation returned no object');
      }
      const info = await source.getImageInfo(0);
      pixelMap = await source.createPixelMap();
      const summary = `bundled PNG decoded=${info.size.width}x${info.size.height}; PixelMap created`;
      this.responseText += `; Image Framework OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `Image Framework decode probe success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText += `; Image Framework ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `Image Framework decode probe failed: ${message}`);
    } finally {
      if (pixelMap) {
        try { await pixelMap.release(); } catch (_) {}
      }
      if (source) {
        try { await source.release(); } catch (_) {}
      }
    }
  }

  /** Prepare a one-second silent WAV created in this HAP's private directory. */
  async probeOwnMediaFile(): Promise<void> {
    this.statusText = 'Preparing a private silent audio sample...';
    hilog.info(DOMAIN, TAG, 'Media service self-file probe started');
    const path = `${getContext(this).filesDir}/vf-media-smoke.wav`;
    const pcmBytes = 8000;
    const wav = new Uint8Array(44 + pcmBytes);
    const header = new DataView(wav.buffer);
    const setText = (offset: number, value: string): void => {
      for (let index = 0; index < value.length; index++) {
        wav[offset + index] = value.charCodeAt(index);
      }
    };
    setText(0, 'RIFF');
    header.setUint32(4, 36 + pcmBytes, true);
    setText(8, 'WAVE');
    setText(12, 'fmt ');
    header.setUint32(16, 16, true);
    header.setUint16(20, 1, true);
    header.setUint16(22, 1, true);
    header.setUint32(24, 8000, true);
    header.setUint32(28, 8000, true);
    header.setUint16(32, 1, true);
    header.setUint16(34, 8, true);
    setText(36, 'data');
    header.setUint32(40, pcmBytes, true);
    wav.fill(0x80, 44);

    let file: fs.File | undefined;
    let player: media.AVPlayer | undefined;
    try {
      const currentFile = fs.openSync(path, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC);
      file = currentFile;
      const written = fs.writeSync(currentFile.fd, wav.buffer);
      if (written !== wav.byteLength) {
        throw new Error(`short write: ${written}/${wav.byteLength}`);
      }
      const currentPlayer = await media.createAVPlayer();
      player = currentPlayer;
      // URL assignment transitions asynchronously from idle to initialized.
      // Wait for that documented state before asking the media service to prepare.
      await new Promise<void>((resolve, reject) => {
        let listener: ((state: media.AVPlayerState, reason: media.StateChangeReason) => void) | undefined;
        const timer = setTimeout(() => {
          if (listener) {
            currentPlayer.off('stateChange', listener);
          }
          reject(new Error(`AVPlayer initialization timed out; state=${currentPlayer.state}`));
        }, 8000);
        listener = (state: media.AVPlayerState, reason: media.StateChangeReason): void => {
          hilog.info(DOMAIN, TAG, `Media player state=${state}; reason=${reason}`);
          if (state === 'initialized') {
            clearTimeout(timer);
            if (listener) {
              currentPlayer.off('stateChange', listener);
            }
            resolve();
          } else if (state === 'error') {
            clearTimeout(timer);
            if (listener) {
              currentPlayer.off('stateChange', listener);
            }
            reject(new Error('AVPlayer entered error state during initialization'));
          }
        };
        currentPlayer.on('stateChange', listener);
        currentPlayer.url = `fd://${currentFile.fd}`;
      });
      await player.prepare();
      const summary = `private WAV prepared; bytes=${written}; state=${player.state}`;
      this.responseText += `; Media service OK: ${summary}`;
      hilog.info(DOMAIN, TAG, `Media service self-file probe success: ${summary}`);
    } catch (err) {
      const message = this.errorMessage(err);
      this.responseText += `; Media service ERROR: ${message}`;
      hilog.error(DOMAIN, TAG, `Media service self-file probe failed: ${message}`);
    } finally {
      if (player) {
        try { await player.release(); } catch (_) {}
      }
      if (file) {
        try { fs.closeSync(file); } catch (_) {}
      }
      try { fs.unlinkSync(path); } catch (_) {}
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
      const code = (err as BusinessError).code;
      return code === undefined ? err.message : `${err.message} (code=${code})`;
    }
    return String(err);
  }

  build() {
    Column() {
      Text('VulnFounder HAP — system-service probe')
        .fontSize(22)
        .fontWeight(FontWeight.Bold)
        .margin({ top: 25, bottom: 10 })

      Text('Bundle / AccessToken / Account / KV / Image / Media / FaultLogger')
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
