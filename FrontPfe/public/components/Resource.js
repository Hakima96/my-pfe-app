import React from 'react';


const Resource = ({ resource, allocate, release }) => {
  return (
    <div>
      <h2>{resource.type}</h2>
      <p>Quantity: {resource.quantity}</p>
      <button onClick={() => allocate(1)}>Allocate</button>
      <button onClick={() => release(1)}>Release</button>
    </div>
  );
};

export default Resource;
