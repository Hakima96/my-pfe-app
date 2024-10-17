import React from 'react';


const Container = ({ container, deployContainer, removeContainer }) => {
  return (
    <div>
      <h2>{container.imageName}</h2>
      <button onClick={() => deployContainer(container.containerID)}>Deploy Container</button>
      <button onClick={() => removeContainer(container.containerID)}>Remove Container</button>
    </div>
  );
};

export default Container;
