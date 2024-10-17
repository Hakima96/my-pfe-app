import React from 'react';


const Service = ({ service, startService, stopService, updateService }) => {
  return (
    <div>
      <h2>{service.serviceName}</h2>
      <p>Status: {service.serviceStatus}</p>
      <button onClick={() => startService(service.serviceID)}>Start Service</button>
      <button onClick={() => stopService(service.serviceID)}>Stop Service</button>
      <button onClick={() => updateService(service.serviceID, 'v2.0')}>Update Service</button>
    </div>
  );
};

export default Service;
