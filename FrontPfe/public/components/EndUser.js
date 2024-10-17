import React from 'react';
import User from './User';


const EndUser = ({ user, accessService, provideFeedback }) => {
  return (
    <div>
      <User user={user} />
      <button onClick={() => accessService('serviceID')}>Access Service</button>
      <button onClick={() => provideFeedback('serviceID', 'Great service!')}>Provide Feedback</button>
    </div>
  );
};

export default EndUser;
