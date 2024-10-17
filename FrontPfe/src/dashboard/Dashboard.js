import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  Container,
  Typography,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  DialogContentText,
  Input,
  Slide,
  Autocomplete,
  Pagination,
  PaginationItem,
  CircularProgress,
  Backdrop,
  Skeleton,
} from "@mui/material";
import Snackbar, { SnackbarCloseReason } from "@mui/material/Snackbar";
import IconButton from "@mui/material/IconButton";
import ServiceCard from "../components/ServiceCard";
import LoadingButton from "@mui/lab/LoadingButton";
import NavMenu from "../components/NavMenu";

function Dashboard() {
  const [options, setoptions] = useState([]);
  const [services, setServices] = useState([]);
  const [TotalPages, setTotalPages] = useState(0);
  const [Page, setPage] = useState(1);
  const [Limit, setLimit] = useState(3);
  const [SearchInput, setSearchInput] = useState("");
  const [openContainer, setopenContainer] = useState(false);
  const [SelectedService, setSelectedService] = useState({});
  const [pageIsLoading, setpageIsLoading] = useState(true);
  const [AccountData, setAccountData] = useState({});
  const [fetchingDataLoading, setfetchingDataLoading] = useState(true);
  const handleContainerOpen = () => {
    setopenContainer(true);
  };

  const handleContainerClose = () => {
    setopenContainer(false);
  };

  const fetchServices = async () => {
    setfetchingDataLoading(true);
    try {

      const response = await axios.get(
        `${process.env.REACT_APP_API_URL}/api/services?limit=${Limit}&page=${Page}&search=${SearchInput}`
      );

      setServices(response.data.services);
      setTotalPages(response.data.total);
      setPage(response.data.page);
    } catch (error) {
      console.error("Erreur lors de la récupération des services", error);
    }
    setfetchingDataLoading(false);
  };

  const fetchServicesNames = async () => {
    try {
      const response = await axios.get(
        `${process.env.REACT_APP_API_URL}/api/services/names`
      );

      setoptions(response.data);
    } catch (error) {
      console.error("Erreur lors de la récupération des services", error);
    }
  };

  const ChangePage = (event, value) => {
    event.preventDefault();
    setPage(value);
  };

  const fetchAccountData = async () => {
    try {
      const token = localStorage.getItem("token");

      const response = await axios.post(
        `${process.env.REACT_APP_API_URL}/api/auth/check-token`,
        {
          token,
        }
      );
      setpageIsLoading(false);
    } catch {
      window.location.href = "/login";
    }
  };

  useEffect(() => {
    fetchServices();
    fetchServicesNames();
    fetchAccountData();
  }, []);

  useEffect(() => {
    fetchServices();
  }, [Page]);

  if (pageIsLoading) {
    return (
      <Backdrop
        sx={(theme) => ({
          color: "primary",
          zIndex: theme.zIndex.drawer + 1,
          backgroundColor: "white",
        })}
        open={pageIsLoading}
      >
        <CircularProgress color="primary" />
      </Backdrop>
    );
  }

  return (
    <div>
      <NavMenu AccountData={AccountData} />
      <Container>
        <Typography
          style={{ marginTop: "20px" }}
          variant="h4"
          component="h2"
          gutterBottom
          color="primary"
        >
          Dashboard
        </Typography>
        <Typography variant="h6" gutterBottom>
          Exécutez vos conteneurs WebAssembly (WASM) en toute simplicité.
          Parcourez vos conteneurs disponibles et lancez-les ou gérez-les
          facilement d'un simple clic. Renforcez vos applications avec des
          services conteneurisés sécurisés et efficaces, directement dans le
          navigateur.
        </Typography>
        <div
          style={{ display: "flex", flexDirection: "row", margin: "10px 0" }}
        >
          <div
            style={{
              display: "flex",
              flexDirection: "row",
              justifyContent: "center",
              alignItems: "center",
              gap: "10px",
            }}
          >
            {/* <Typography style={{ margin: "0" }} variant="h6" gutterBottom>
              Search:
            </Typography> */}
            <Autocomplete
              freeSolo
              options={options}
              inputValue={SearchInput}
              onInputChange={(event, newInputValue) => {
                setSearchInput(newInputValue);
              }}
              sx={{ width: 300 }}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Service"
                  size="small"

                />
              )}
            />
            <Button
              color="primary"
              variant="contained"
              onClick={() => {
                fetchServices();
              }}
            >
              Search
            </Button>
          </div>
        </div>
        {/* <hr style={{ borderColor: "#D3D3D3" }} /> */}
        {fetchingDataLoading ? (
          <div>
            <Skeleton height={60} />
            <Skeleton height={60} />
            <Skeleton height={60} />
          </div>
        ) : (
          services.map((service) => {
            return (
              <ServiceCard
                service={service}
                key={service._id}
                setSelectedService={setSelectedService}
                setopenContainer={setopenContainer}
              />
            );
          })
        )}
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            margin: "20px 0",
          }}
        >
          <Pagination
            count={TotalPages}
            size="large"
            page={Page}
            onChange={ChangePage}
          />
        </div>
        <Dialog
          open={openContainer}
          TransitionComponent={Transition}
          maxWidth="lg"
          onClose={handleContainerClose}
          aria-describedby="alert-dialog-slide-description"
        >
          <DialogTitle color="primary">{SelectedService.name}</DialogTitle>
          <DialogContent>
            <iframe
              style={{
                border: "0",
                width: "60vw",
                height: "60vh",
              }}
              src={`${process.env.REACT_APP_API_URL}/${SelectedService.url}`}
            ></iframe>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => {
                setSelectedService({});
                handleContainerClose();
              }}
            >
              Close
            </Button>
          </DialogActions>
        </Dialog>
      </Container>
    </div>
  );
}

export default Dashboard;
const Transition = React.forwardRef(function Transition(props, ref) {
  return <Slide direction="up" ref={ref} {...props} />;
});
