import React, { useEffect } from "react";
import { CircularProgress, Backdrop } from "@mui/material";
import axios from "axios";
function App() {
  const fetchAccountData = async () => {
    try {
      const token = localStorage.getItem("token");

      const response = await axios.post(
        `${process.env.REACT_APP_API_URL}/api/auth/check-token`,
        {
          token,
        }
      );

      if (response.status === 200) {
        window.location.href = "./dashboard";
      }
    } catch (error) {
      console.log(error);
      window.location.href = "./login";
      
    }
  };
  useEffect(() => {
    fetchAccountData();
  }, []);
  return (
    <Backdrop
      sx={(theme) => ({
        color: "primary",
        zIndex: theme.zIndex.drawer + 1,
        backgroundColor: "white",
      })}
      open={true}
    >
      <CircularProgress color="primary" />
    </Backdrop>
  );
}

export default App;
