import {
  Chart,
  ChartAxis,
  ChartBar,
  ChartLabel,
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
  const showTickValues = props.every((item) => {
    return (
      item.vulnerabilities.critical +
        item.vulnerabilities.high +
        item.vulnerabilities.low +
        item.vulnerabilities.none ===
      0
    );
  });

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
          left: 330,
          right: 50,
          top: 50,
        }}
        themeColor={ChartThemeColor.multiOrdered}
        width={700}
        legendComponent={
          <ChartLegend
            y={10}
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
        <ChartAxis
          label="Products"
          axisLabelComponent={<ChartLabel dx={0} x={10} y={140} />}
          tickLabelComponent={
            <ChartLabel
              className="pf-v5-c-button pf-m-link pf-m-inline"
              style={[{ fill: '#0066cc' }]}
              events={{
                onClick: (event) => {
                  const sbom_name = (event.target as any).innerHTML as string | null;
                  const sbom = props.find((item) => item.sbom_name === sbom_name);
                  if (sbom) {
                    window.open(`/sbom/content/${sbom.sbom_id}`);
                  }
                },
              }}
            />
          }
        />
        <ChartAxis
          dependentAxis
          showGrid
          tickValues={showTickValues ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] : undefined}
          label="CVEs by Severity"
          fixLabelOverlap={true}
        />
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
