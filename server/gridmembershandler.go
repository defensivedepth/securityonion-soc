// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"errors"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi"
)

type GridMembersHandler struct {
	server *Server
}

func RegisterGridMemberRoutes(srv *Server, r chi.Router, prefix string) {
	h := &GridMembersHandler{
		server: srv,
	}

	r.Route(prefix, func(r chi.Router) {
		r.Use(h.gridMembersEnabled)

		r.Get("/", h.getGridMembers)

		r.Post("/{id}/{operation}", h.postManageMembers)
	})
}

func (h *GridMembersHandler) gridMembersEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.server.GridMembersstore == nil {
			web.Respond(w, r, http.StatusMethodNotAllowed, errors.New("GridMembers module not enabled"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *GridMembersHandler) getGridMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	members, err := h.server.GridMembersstore.GetMembers(ctx)
	if err != nil {
		web.Respond(w, r, http.StatusInternalServerError, err)
		return
	}

	web.Respond(w, r, http.StatusOK, members)
}

func (h *GridMembersHandler) postManageMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if !model.IsValidMinionId(id) {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid minion ID"))
		return
	}

	op := chi.URLParam(r, "operation")
	if op != "add" && op != "reject" && op != "delete" && op != "test" {
		web.Respond(w, r, http.StatusBadRequest, errors.New("Invalid operation"))
		return
	}

	err := h.server.GridMembersstore.ManageMember(ctx, op, id)
	if err != nil {
		web.Respond(w, r, http.StatusBadRequest, err)
		return
	}

	web.Respond(w, r, http.StatusOK, nil)
}
