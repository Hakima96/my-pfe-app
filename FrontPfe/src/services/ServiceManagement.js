import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  Container,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  DialogContentText,
  Slide,
  Pagination,
  CircularProgress,
  Backdrop,
} from "@mui/material";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import IconButton from "@mui/material/IconButton";
import { Close } from "@mui/icons-material";
import { LoadingButton } from "@mui/lab";
import NavMenu from "../components/NavMenu";

const Transition = React.forwardRef(function Transition(props, ref) {
  return <Slide direction="up" ref={ref} {...props} />;
});

function ServiceManagement() {
  const [services, setServices] = useState([]);
  const [TotalPages, setTotalPages] = useState(0);
  const [Page, setPage] = useState(1);
  const [Limit, setLimit] = useState(5);
  const [SearchInput, setSearchInput] = useState("");
  const [Selectedservices, setSelectedServices] = useState({});
  const [newService, setNewService] = useState({
    name: "",
    description: "",
  });
  const [open, setOpen] = useState(false);
  const [openConfirmation, setOpenConfirmation] = React.useState(false);
  const [openEdit, setOpenEdit] = React.useState(false);
  const [messageSnackBar, setmessageSnackBar] = useState("");
  const [openSnackBar, setopenSnackBar] = useState(false);
  const [loading, setloading] = useState(false);
  const [FileUpload, setFileUpload] = useState([]);
  const [AccountData, setAccountData] = useState({});
  const [severityType, setseverityType] = useState("");
  const severity = {
    success: "success",
    info: "info",
    error: "error",
    warning: "warning",
  };

  const [pageIsLoading, setpageIsLoading] = useState(true);

  const handleEditClickOpen = () => {
    setOpenEdit(true);
  };

  const handleEditClose = () => {
    setOpenEdit(false);
  };

  const handleConfirmationClickOpen = () => {
    setOpenConfirmation(true);
  };

  const handleConfirmationClose = () => {
    setOpenConfirmation(false);
  };

  const handleClickSnackBar = () => {
    setopenSnackBar(true);
  };

  const handleCloseSnackBar = (event, reason) => {
    if (reason === "clickaway") {
      return;
    }
    setopenSnackBar(false);
  };

  const action = (
    <React.Fragment>
      <IconButton
        size="small"
        aria-label="close"
        color="inherit"
        onClick={handleCloseSnackBar}
      >
        {/* <CloseIcon fontSize="small" /> */}
        <Close fontSize="small" />
      </IconButton>
    </React.Fragment>
  );

  const fetchServices = async () => {
    try {
      const response = await axios.get(
        `${process.env.REACT_APP_API_URL}/api/services?limit=${Limit}&page=${Page}&search=${SearchInput}`
      );
      setTotalPages(response.data.total);
      setPage(response.data.page);
      setServices(response.data.services);
    } catch (error) {
      console.error("Erreur lors de la récupération des services", error);
    }
  };

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleChange = (e) => {
    setNewService({ ...newService, [e.target.name]: e.target.value });
  };

  const handleUpdate = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();

      if (!newService.name) {
        setseverityType(severity.warning);
        setmessageSnackBar("Veuillez saisir un nom pour le service");
        handleClickSnackBar();
        return;
      }
      formData.append("name", newService.name);

      if (!newService.description) {
        setseverityType(severity.warning);

        setmessageSnackBar("Veuillez saisir une description pour le service");
        handleClickSnackBar();
        return;
      }
      formData.append("description", newService.description);

      if (FileUpload.length !== 0) {
        for (let i = 0; i < FileUpload.length; i++) {
          formData.append("container", FileUpload[i]);
        }
      }

      setmessageSnackBar("Attendez s'il vous plait...");
      setseverityType(severity.info);

      handleClickSnackBar();
      await axios.put(
        `${process.env.REACT_APP_API_URL}/api/services/${newService._id}`,
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );
      setseverityType(severity.success);

      setmessageSnackBar("service mis à jour avec succès");

      fetchServices();
      handleClose();
    } catch (error) {
      setseverityType(severity.error);

      console.error("Erreur lors de l'ajout du service", error);
      setmessageSnackBar("Erreur lors de l'ajout du service");
      handleClickSnackBar();
    }
    handleEditClose();
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      setloading(true);

      if (!newService.name) {
        setmessageSnackBar("Veuillez saisir un nom pour le service");
        setseverityType(severity.warning);
        setloading(false);

        handleClickSnackBar();
        return;
      }
      formData.append("name", newService.name);

      if (!newService.description) {
        setmessageSnackBar("Veuillez saisir une description pour le service");
        setseverityType(severity.warning);

        handleClickSnackBar();
        setloading(false);
        return;
      }
      formData.append("description", newService.description);

      if (FileUpload.length === 0) {
        setmessageSnackBar("Veuillez sélectionner un fichier");
        setseverityType(severity.warning);
        setloading(false);
        handleClickSnackBar();
        setloading(false);
        return;
      }
      for (let i = 0; i < FileUpload.length; i++) {
        formData.append("container", FileUpload[i]);
      }

      setmessageSnackBar("Attendez s'il vous plait...");
      setseverityType(severity.info);

      handleClickSnackBar();
      await axios.post(
        `${process.env.REACT_APP_API_URL}/api/services`,
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );
      setmessageSnackBar("Service ajouté avec succès");
      setseverityType(severity.success);
      handleClickSnackBar();
      await fetchServices();
      handleClose();
    } catch (error) {
      console.error("Erreur lors de l'ajout du service", error);
      setmessageSnackBar("Erreur lors de l'ajout du service");
      setseverityType(severity.error);

      handleClickSnackBar();
    }
    setloading(false);
  };

  const DeleteService = async () => {
    try {
      const response = await axios.delete(
        `${process.env.REACT_APP_API_URL}/api/services/${
          Selectedservices._id || ""
        }`
      );
      setmessageSnackBar("Service supprimé avec succès");
      setseverityType(severity.success);

      handleClickSnackBar();
      fetchServices();
      setSelectedServices({});
    } catch (error) {
      console.error("Erreur lors de la suppression des services", error);
      setseverityType(severity.error);

      setmessageSnackBar("Erreur lors de la suppression du service");
      handleClickSnackBar();
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
      setAccountData(response.data);
    } catch {
      window.location.href = "/login";
    }
  };

  useEffect(() => {
    fetchServices();
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
        <div
          style={{
            margin: "20px 0",
            display: "flex",
            flexDirection: "row",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Typography
            variant="h4"
            component="h2"
            gutterBottom
            style={{ margin: "0" }}
          >
            Gestion des Services Web
          </Typography>
          <Button variant="contained" color="primary" onClick={handleOpen}>
            Ajouter un service
          </Button>
        </div>
        <TableContainer component={Paper} sx={{ mt: 2 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Nom</TableCell>
                <TableCell>Description</TableCell>
                <TableCell>URL</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {services.map((service) => (
                <TableRow key={service._id}>
                  <TableCell>{service.name}</TableCell>
                  <TableCell>{service.description}</TableCell>
                  <TableCell>{service.url}</TableCell>
                  <TableCell>
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={() => {
                        setNewService(service);
                        handleEditClickOpen();
                      }}
                      style={{ margin: "2px" }}
                    >
                      Éditer
                    </Button>
                    <Button
                      style={{ margin: "2px" }}
                      variant="outlined"
                      color="error"
                      size="small"
                      onClick={() => {
                        setSelectedServices(service);
                        handleConfirmationClickOpen();
                      }}
                    >
                      Supprimer
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <Dialog open={openEdit} onClose={handleEditClose}>
          <DialogTitle>Mettre a jour service</DialogTitle>
          <DialogContent>
            <TextField
              autoFocus
              margin="dense"
              name="name"
              label="Nom du service"
              type="text"
              fullWidth
              variant="standard"
              value={newService.name}
              onChange={handleChange}
            />
            <TextField
              margin="dense"
              name="description"
              label="Description"
              type="text"
              fullWidth
              variant="standard"
              value={newService.description}
              onChange={handleChange}
            />
            <form>
              <TextField
                margin="dense"
                name="url"
                type="file"
                fullWidth
                variant="standard"
                onChange={(e) => setFileUpload(e.target.files)}
                inputProps={{
                  multiple: true,
                }}
              />
            </form>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleEditClose}>Annuler</Button>
            <Button onClick={handleUpdate} color="success">
              Mettre à Jour
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog open={open} onClose={handleClose}>
          <DialogTitle>Ajouter un nouveau service</DialogTitle>
          <DialogContent>
            <TextField
              autoFocus
              margin="dense"
              name="name"
              label="Nom du service"
              type="text"
              fullWidth
              variant="standard"
              value={newService.name}
              onChange={handleChange}
            />
            <TextField
              margin="dense"
              name="description"
              label="Description"
              type="text"
              fullWidth
              variant="standard"
              value={newService.description}
              onChange={handleChange}
            />
            <form>
              <TextField
                margin="dense"
                name="url"
                type="file"
                fullWidth
                variant="standard"
                onChange={(e) => setFileUpload(e.target.files)}
                inputProps={{
                  multiple: true,
                }}
              />
            </form>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleClose}>Annuler</Button>
            {/* <Button onClick={handleSubmit} color="success">
              Ajouter
            </Button> */}
            <LoadingButton
              onClick={handleSubmit}
              loading={loading}
              loadingPosition="end"
              variant="contained"
              color="success"
            >
              Ajouter
            </LoadingButton>
          </DialogActions>
        </Dialog>
        <Dialog
          open={openConfirmation}
          TransitionComponent={Transition}
          maxWidth="md"
          keepMounted
          onClose={handleConfirmationClose}
          aria-describedby="alert-dialog-slide-description"
        >
          <DialogTitle>Confirmation</DialogTitle>
          <DialogContent>
            <DialogContentText id="alert-dialog-slide-description">
              Are you sure to Delete {Selectedservices.name || ""} Service ?
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleConfirmationClose}>Cancel</Button>
            <Button
              onClick={() => {
                DeleteService();
                handleConfirmationClose();
              }}
              color="error"
            >
              Delete
            </Button>
          </DialogActions>
        </Dialog>
        <Snackbar
          open={openSnackBar}
          autoHideDuration={3000}
          onClose={handleCloseSnackBar}
          action={action}
        >
          <Alert
            severity={severityType}
            variant="filled"
            sx={{ width: "100%" }}
          >
            {messageSnackBar}
          </Alert>
        </Snackbar>
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
      </Container>
    </div>
  );
}

export default ServiceManagement;
