import React from 'react';


const SecurityAuditor = ({ conductSecurityAudit, recommendSecurityImprovements }) => {
  return (
    <div>
      <button onClick={() => conductSecurityAudit()}>Conduct Security Audit</button>
      <button onClick={() => recommendSecurityImprovements({ reportID: '123', findings: 'None' })}>Recommend Security Improvements</button>
    </div>
  );
};

export default SecurityAuditor;
