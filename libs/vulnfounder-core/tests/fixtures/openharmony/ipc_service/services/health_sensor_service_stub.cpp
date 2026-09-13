// Synthetic Binder stub used only by VulnFounder tests.
#include "i_health_sensor_service.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"

namespace OHOS {
namespace VulnFounderFixture {

HealthSensorServiceStub::HealthSensorServiceStub()
{
    handlers_[IHealthSensorService::ENABLE_SENSOR] =
        &HealthSensorServiceStub::EnableSensorInner;
}

int32_t HealthSensorServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    const std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != IHealthSensorService::GetDescriptor()) {
        return ERR_INVALID_STATE;
    }

    const auto handler = handlers_.find(code);
    if (handler == handlers_.end() || handler->second == nullptr) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return (this->*(handler->second))(data, reply);
}

int32_t HealthSensorServiceStub::EnableSensorInner(
    MessageParcel &data, MessageParcel &reply)
{
    (void)reply;
    const uint32_t sensorId = data.ReadUint32();
    const int64_t samplingPeriodNs = data.ReadInt64();
    const AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    const int32_t permission = AccessTokenKit::VerifyAccessToken(
        callerToken, "ohos.permission.READ_HEALTH_DATA");
    if (permission != PERMISSION_GRANTED) {
        return ERR_PERMISSION_DENIED;
    }
    return EnableSensor(sensorId, samplingPeriodNs);
}

}  // namespace VulnFounderFixture
}  // namespace OHOS
