/**
 * TriggerService.ets — 后台服务（简化版）
 */
import ServiceExtension from '@ohos.app.ability.ServiceExtensionAbility';
import hilog from '@ohos.hilog';

const DOMAIN = 0x0001;
const TAG = 'TriggerService';

export default class TriggerService extends ServiceExtension {
  onCreate(want): void {
    hilog.info(DOMAIN, TAG, 'TriggerService onCreate');
  }

  onRequest(want, startId): void {
    hilog.info(DOMAIN, TAG, `TriggerService onRequest, startId=${startId}`);
  }

  onConnect(want): rpc.RemoteObject {
    hilog.info(DOMAIN, TAG, 'TriggerService onConnect');
    return null;
  }

  onDisconnect(want): void {
    hilog.info(DOMAIN, TAG, 'TriggerService onDisconnect');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'TriggerService onDestroy');
  }
}

import rpc from '@ohos.rpc';
