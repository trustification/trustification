var chartValues = {
  ariaDesc: 'Average number of pets',
  ariaTitle: 'Donut chart example',
  constrainToVisibleArea: true,
  data: [
    { x: 'Cats', y: 35 },
    { x: 'Dogs', y: 55 },
    { x: 'Birds', y: 10 },
  ],
  labels: ({ datum }) => `${datum.x}: ${datum.y}%`,
  legendData: [{ name: 'Cats: 35' }, { name: 'Dogs: 55' }, { name: 'Birds: 10' }],
  legendOrientation: 'vertical',
  legendPosition: 'right',
  name: 'chart2',
  padding: { bottom: 20, left: 20, right: 140, top: 20 },
  subTitle: 'Pets',
  title: '100',
  width: 350,
};

// Render
Patternfly.ChartDonutRenderer(document.getElementById('root'), chartValues);
