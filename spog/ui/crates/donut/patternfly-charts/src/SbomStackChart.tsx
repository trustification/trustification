import {
  Chart,
  ChartAxis,
  ChartBar,
  ChartLegend,
  ChartStack,
  ChartThemeColor,
  ChartTooltip,
} from '@patternfly/react-charts';
import React from 'react';
import ReactDOM from 'react-dom/client';

import noneColor from '@patternfly/react-tokens/dist/esm/global_palette_black_400';
import lowColor from '@patternfly/react-tokens/dist/esm/chart_color_blue_200';
import mediumColor from '@patternfly/react-tokens/dist/esm/chart_color_gold_300';
import highColor from '@patternfly/react-tokens/dist/esm/chart_color_red_100';
import criticalColor from '@patternfly/react-tokens/dist/esm/chart_color_red_300';

interface StackChartProps {
  sbom_id: string;
  sbom_name: string;
  vulnerabilities: {
    none: number;
    low: number;
    high: number;
    critical: number;
  };
}

export const SbomStackChartRenderer = (htmlElement: HTMLElement, props: StackChartProps[]) => {
  const severities = [
    { name: 'Critical' },
    { name: 'High' },
    { name: 'Medium' },
    { name: 'Low' },
    { name: 'None' },
  ];

  const root = ReactDOM.createRoot(htmlElement);
  root.render(
    <React.StrictMode>
      <Chart
        ariaDesc="SBOM summary status"
        domainPadding={{ x: [30, 25] }}
        legendData={severities}
        legendPosition="bottom-left"
        height={375}
        name="sbom-summary-status"
        padding={{
          bottom: 75,
          left: 80,
          right: 50,
          top: 50,
        }}
        themeColor={ChartThemeColor.multiOrdered}
        width={450}
        legendComponent={
          <ChartLegend
            colorScale={[
              criticalColor.var,
              highColor.var,
              mediumColor.var,
              lowColor.var,
              noneColor.var,
            ]}
          />
        }
      >
        <ChartAxis />
        <ChartAxis dependentAxis showGrid />
        <ChartStack
          horizontal
          colorScale={[
            criticalColor.var,
            highColor.var,
            mediumColor.var,
            lowColor.var,
            noneColor.var,
          ]}          
        >
          {severities.map((severity) => (
            <ChartBar
              key={severity.name}
              labelComponent={<ChartTooltip constrainToVisibleArea />}
              data={props.map((sbom) => {
                const severityKey = severity.name.toLowerCase();
                const count = (sbom.vulnerabilities as any)[severityKey] as number;
                return {
                  name: severity.name,
                  x: sbom.sbom_name,
                  y: count,
                  label: `${severity.name}: ${count}`,
                };
              })}
            />
          ))}
        </ChartStack>
      </Chart>
    </React.StrictMode>,
  );
};
