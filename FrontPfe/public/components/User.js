import React, { useState } from 'react';

const User = ({ user }) => {
  const [loggedIn, setLoggedIn] = useState(false);

  const login = () => setLoggedIn(true);
  const logout = () => setLoggedIn(false);

  return (
    <div>
      <h2>{user.userName}</h2>
      <p>{user.userEmail}</p>
      {loggedIn ? (
        <button onClick={logout}>Logout</button>
      ) : (
        <button onClick={login}>Login</button>
      )}
    </div>
  );
};

export default User;
