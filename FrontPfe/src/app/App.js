import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Register from '../register/Register';
import Login from '../login/Login';
import ServiceManagement from '../services/ServiceManagement';
import Dashboard from '../dashboard/Dashboard';
import RouterConfig from '../RouterConfig/RouterConfig';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/services" element={<ServiceManagement />} />
        <Route path="/" element={<RouterConfig />} />
      </Routes>
    </Router>
  );
}

export default App;