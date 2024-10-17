import React from 'react';
import User from './User';


const WebServiceDeveloper = ({ user, deployService, migrateService, updateService }) => {
  return (
    <div>
      <User user={user} />
      <button onClick={() => deployService({ containerID: '123' })}>Deploy Service</button>
      <button onClick={() => migrateService('serviceID', 'targetEnvironment')}>Migrate Service</button>
      <button onClick={() => updateService({ serviceID: 'serviceID', newVersion: 'v2.0' })}>Update Service</button>
    </div>
  );
};

export default WebServiceDeveloper;
