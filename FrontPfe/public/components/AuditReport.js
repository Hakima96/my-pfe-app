import React from 'react';

const AuditReport = ({ report }) => {
  return (
    <div>
      <h2>Audit Report</h2>
      <p>{report.findings}</p>
    </div>
  );
};

export default AuditReport;
