import React from 'react';
import User from './User';


const Admin = ({ user, createUserService, deleteUser, configureSystemSettings }) => {
  return (
    <div>
      <User user={user} />
      <button onClick={() => createUserService(user)}>Create User Service</button>
      <button onClick={() => deleteUser(user.userID)}>Delete User</button>
      <button onClick={() => configureSystemSettings({ settingName: 'example', settingValue: 'value' })}>Configure System Settings</button>
    </div>
  );
};

export default Admin;
