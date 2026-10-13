/**
 * Logger.ets
 * 统一日志工具 — 封装 HiLog，方便统一管理日志级别和格式
 */
import hilog from '@ohos.hilog';

const DOMAIN = 0x0001;

export enum LogLevel {
  DEBUG = 3,
  INFO = 4,
  WARN = 5,
  ERROR = 6,
}

export class Logger {
  private tag: string;

  constructor(tag: string) {
    this.tag = tag;
  }

  debug(msg: string, ...args: Object[]): void {
    hilog.debug(DOMAIN, this.tag, msg, ...args);
  }

  info(msg: string, ...args: Object[]): void {
    hilog.info(DOMAIN, this.tag, msg, ...args);
  }

  warn(msg: string, ...args: Object[]): void {
    hilog.warn(DOMAIN, this.tag, msg, ...args);
  }

  error(msg: string, ...args: Object[]): void {
    hilog.error(DOMAIN, this.tag, msg, ...args);
  }

  /**
   * 记录测试结果（结构化日志）
   */
  logResult(testName: string, payloadType: string, payloadLen: number,
    status: string, response: string, error: string = ''): void {
    hilog.info(DOMAIN, this.tag,
      `[RESULT] test=${testName} type=${payloadType} len=${payloadLen} status=${status} err=${error}`);
    if (response) {
      hilog.info(DOMAIN, this.tag, `[RESPONSE] ${response.substring(0, 200)}`);
    }
  }
}
