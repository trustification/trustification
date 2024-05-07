module.exports = {
  webpack: {
    configure: (webpackConfig) => {
      webpackConfig.output = {
        ...webpackConfig.output,
        filename: 'static/js/main.js',

        library: {
          type: 'module',
        },
        libraryTarget: 'module',
      };
      webpackConfig.experiments = {
        outputModule: true,
      };
      webpackConfig.optimization = {
        ...webpackConfig.optimization,
        runtimeChunk: false, // For single main.js
        splitChunks: {
          cacheGroups: {
            default: false,
            vendors: false,
          },
        },
      };

      // inline all assets into the JS bundle
      webpackConfig.module.rules[0].oneOf.unshift({
        test: /\.(png|jpg|jpeg|woff|woff2|eot|ttf|svg)$/,
        type: 'asset/inline',
      });

      return webpackConfig;
    },
  },
  plugins: [
    {
      plugin: {
        overrideWebpackConfig: ({ webpackConfig }) => {
          webpackConfig.plugins[5].options.filename = 'static/css/[name].css';
          return webpackConfig;
        },
      },
      options: {},
    },
  ],
};
