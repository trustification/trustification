import React from 'react';
import ReactDOM from 'react-dom/client';
import { ChartDonut, ChartDonutProps } from '@patternfly/react-charts';

export const ChartDonutRenderer = (htmlElement: HTMLElement, props: ChartDonutProps) => {
  const root = ReactDOM.createRoot(htmlElement);
  root.render(
    <React.StrictMode>
      <ChartDonut {...props} />
    </React.StrictMode>,
  );
};
