import * as React from "react";
import Accordion from "@mui/material/Accordion";
import {
  AccordionDetails,
  AccordionSummary,
  AccordionActions,
  Button,
} from "@mui/material";
import Typography from "@mui/material/Typography";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";

export default function ServiceCard({
  service,
  setSelectedService,
  setopenContainer,
}) {
  const [expanded, setExpanded] = React.useState(false);

  const handleExpansion = () => {
    setExpanded((prevExpanded) => !prevExpanded);
  };

  return (
    <Accordion style={{ margin: "10px 0" }}>
      <AccordionSummary
        expandIcon={<ExpandMoreIcon />}
        aria-controls="panel3-content"
        id="panel3-header"
      >
        <Typography>{service.name}</Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Typography>{service.description}</Typography>
      </AccordionDetails>
      <AccordionActions>
        <Button
          onClick={() => {
            if (setSelectedService) {
              setSelectedService(service);
            }
            if (setopenContainer) {
              setopenContainer(true);
            }
          }}
        >
          Run
        </Button>
      </AccordionActions>
    </Accordion>
  );
}
