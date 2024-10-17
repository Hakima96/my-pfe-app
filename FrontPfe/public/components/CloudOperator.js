import React from 'react';


const CloudOperator = ({ operator, allocateResources, monitorResourceUsage }) => {
  return (
    <div>
      <h2>{operator.operatorID}</h2>
      <button onClick={() => allocateResources('serviceID', [{ type: 'CPU', quantity: 2 }])}>Allocate Resources</button>
      <button onClick={() => monitorResourceUsage()}>Monitor Resource Usage</button>
    </div>
  );
};

export default CloudOperator;
