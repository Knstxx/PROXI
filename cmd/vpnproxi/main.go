package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"vpnproxi/internal/app"
	"vpnproxi/internal/system"
)

//go:embed static/*
var staticFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	statePath := flag.String("state", defaultStatePath(), "state JSON path")
	logPath := flag.String("log", defaultLogPath(), "activity log path")
	authPath := flag.String("auth", defaultAuthPath(), "admin credentials JSON path")
	applyEnabled := flag.Bool("apply-enabled", true, "allow API to write system files and restart services")
	createAdmin := flag.Bool("create-admin", false, "create or replace admin credentials and exit")
	adminUsername := flag.String("admin-username", "", "admin username for --create-admin")
	applyOnce := flag.Bool("apply-once", false, "apply current state to host and exit")
	flag.Parse()

	if *createAdmin {
		password := os.Getenv("VPNPROXI_ADMIN_PASSWORD")
		if err := app.WriteAuthFile(*authPath, *adminUsername, password); err != nil {
			log.Fatal(err)
		}
		log.Printf("admin credentials written to %s", *authPath)
		return
	}

	if *applyOnce {
		state, err := app.NewStore(*statePath).Load()
		if err != nil {
			log.Fatal(err)
		}
		result, err := system.Apply(state)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("changedFiles=%d commands=%d warnings=%d\n", len(result.ChangedFiles), len(result.Commands), len(result.Warnings))
		for _, warning := range result.Warnings {
			fmt.Printf("warning: %s\n", warning)
		}
		return
	}

	svc, err := app.NewService(app.Options{
		StatePath:    *statePath,
		LogPath:      *logPath,
		StaticFS:     staticFS,
		ApplyEnabled: *applyEnabled,
		AdminToken:   os.Getenv("VPNPROXI_ADMIN_TOKEN"),
		AuthPath:     *authPath,
	})
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           svc.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("vpnproxi listening on %s state=%s log=%s apply=%v", *addr, *statePath, *logPath, *applyEnabled)
	log.Fatal(server.ListenAndServe())
}

func defaultStatePath() string {
	if v := os.Getenv("VPNPROXI_STATE"); v != "" {
		return v
	}
	return "/etc/vpnproxi/state.json"
}

func defaultLogPath() string {
	if v := os.Getenv("VPNPROXI_LOG"); v != "" {
		return v
	}
	return "/var/log/vpnproxi/vpnproxi.log"
}

func defaultAuthPath() string {
	if v := os.Getenv("VPNPROXI_AUTH"); v != "" {
		return v
	}
	return "/etc/vpnproxi/admin.json"
}
