package web

import log "github.com/sirupsen/logrus"

type WebRunner interface {
	Run(addr string) error
}

func RunWebServer(r WebRunner, addr string, fatal bool) {
	go func() {
		if err := r.Run(addr); err != nil {
			if fatal {
				log.WithError(err).Fatal("web server exited")
			} else {
				log.WithError(err).Error("web server exited")
			}
		}
	}()
}
