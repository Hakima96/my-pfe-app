import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import {
  Container, TextField, Button, Typography, Box, Alert, CircularProgress
} from '@mui/material';

function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post(`${process.env.REACT_APP_API_URL}/api/auth/register`, { email, password });
      setMessage('Inscription réussie !');
      setTimeout(() => navigate('/login'), 2000);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Erreur lors de l\'inscription');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h5">Inscription</Typography>
        {message && <Alert severity={message.includes('réussie') ? 'success' : 'error'}>{message}</Alert>}
        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
          <TextField
            margin="normal" required fullWidth id="email" label="Adresse email"
            name="email" autoComplete="email" autoFocus
            value={email} onChange={(e) => setEmail(e.target.value)}
          />
          <TextField
            margin="normal" required fullWidth name="password" label="Mot de passe"
            type="password" id="password" autoComplete="new-password"
            value={password} onChange={(e) => setPassword(e.target.value)}
          />
          <Button
            type="submit" fullWidth variant="contained" sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'S\'inscrire'}
          </Button>
          <Link to="/login" style={{ textDecoration: 'none' }}>
            <Typography variant="body2" align="center">
              Déjà un compte ? Connectez-vous
            </Typography>
          </Link>
        </Box>
      </Box>
    </Container>
  );
}

export default Register;
