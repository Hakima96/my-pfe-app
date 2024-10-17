import React from 'react';


const SystemSettings = ({ settings, updateSetting }) => {
  return (
    <div>
      <h2>{settings.settingName}</h2>
      <input
        type="text"
        value={settings.settingValue}
        onChange={(e) => updateSetting(settings.settingName, e.target.value)}
      />
    </div>
  );
};

export default SystemSettings;
