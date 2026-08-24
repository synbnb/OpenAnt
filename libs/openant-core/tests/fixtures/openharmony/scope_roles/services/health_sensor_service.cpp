#include "health_sensor_service.h"

int EnableHealthSensor(int sensor_id)
{
    return sensor_id >= 0 ? 0 : -1;
}
