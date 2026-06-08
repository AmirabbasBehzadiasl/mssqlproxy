package config

import "github.com/spf13/viper"

type Config struct {
	ListenAddr   string `mapstructure:"listen_addr"`
	UpstreamAddr string `mapstructure:"upstream_addr"`
	CertFile     string `mapstructure:"cert_file"`
	KeyFile      string `mapstructure:"key_file"`
	LogLevel     string `mapstructure:"log_level"`
}

func Load(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetDefault("log_level", "info")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}