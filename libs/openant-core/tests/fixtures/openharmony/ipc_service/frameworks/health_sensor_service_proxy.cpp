// Synthetic Binder proxy used only by OpenAnt tests.
#include "i_health_sensor_service.h"

#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace OpenAntFixture {

int32_t HealthSensorServiceProxy::EnableSensor(uint32_t sensorId, int64_t samplingPeriodNs)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(IHealthSensorService::GetDescriptor())) {
        return ERR_INVALID_DATA;
    }
    if (!data.WriteUint32(sensorId) || !data.WriteInt64(samplingPeriodNs)) {
        return ERR_INVALID_DATA;
    }
    return Remote()->SendRequest(IHealthSensorService::ENABLE_SENSOR, data, reply, option);
}

}  // namespace OpenAntFixture
}  // namespace OHOS
