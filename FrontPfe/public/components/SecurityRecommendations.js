import React from 'react';


const SecurityRecommendations = ({ recommendations, applyRecommendations }) => {
  return (
    <div>
      <h2>Security Recommendations</h2>
      <p>{recommendations.recommendations}</p>
      <button onClick={() => applyRecommendations(recommendations.recommendationID)}>Apply Recommendations</button>
    </div>
  );
};

export default SecurityRecommendations;
