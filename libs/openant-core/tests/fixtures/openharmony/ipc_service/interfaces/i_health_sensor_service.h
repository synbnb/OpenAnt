#ifndef OPENANT_FIXTURE_I_HEALTH_SENSOR_SERVICE_H
#define OPENANT_FIXTURE_I_HEALTH_SENSOR_SERVICE_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace OpenAntFixture {

class IHealthSensorService {
public:
    enum Transaction : uint32_t {
        ENABLE_SENSOR = 1,
    };

    static std::u16string GetDescriptor()
    {
        return u"ohos.openant.fixture.IHealthSensorService";
    }
};

}  // namespace OpenAntFixture
}  // namespace OHOS

#endif  // OPENANT_FIXTURE_I_HEALTH_SENSOR_SERVICE_H
