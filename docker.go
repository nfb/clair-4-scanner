package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/docker/docker/client"
)

// TODO Add support for older version of docker

type manifestJSON struct {
	Config string
	Layers []string
}

type configJSON struct {
	//rootfs rootfsJSON `json:"rootfs"`
	Rootfs struct {
		Diff_ids []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type rootfsJSON struct {
	diff_ids []string `json:"diff_ids"`
}

type clairLayer struct {
	Hash string `json:"hash"`
	Uri  string `json:"uri"`
}

type clairManifest struct {
	Hash   string       `json:"hash"`
	Layers []clairLayer `json:"layers"`
}

// saveDockerImage saves Docker image to temorary folder
func saveDockerImage(imageName string, tmpPath string) {
	docker := createDockerClient()

	imageReader, err := docker.ImageSave(context.Background(), []string{imageName})
	if err != nil {
		logger.Fatalf("Could not save Docker image [%s]: %v", imageName, err)
	}

	defer imageReader.Close()

	if err = untar(imageReader, tmpPath); err != nil {
		logger.Fatalf("Could not save Docker image: could not untar [%s]: %v", imageName, err)
	}
}

func createDockerClient() client.APIClient {
	docker, err := client.NewEnvClient()
	if err != nil {
		logger.Fatalf("Could not create a Docker client: %v", err)
	}
	return docker
}

// getImageLayerIds reads LayerIDs from the manifest.json file
func getImageLayerIds(path string) []string {
	manifest := readManifestFile(path)

	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers
}

// Generates a manifest struct using docker image bits which can be used in a post request to indexer
func getClairManifest(path string) *clairManifest {
	manifest := readManifestFile(path)
	manifestSha, _, _ := strings.Cut(manifest[0].Config, ".json")
	config := getConfigFileShas(path, manifestSha)
	var cm clairManifest
	cm.Hash = "sha256:" + manifestSha
	for i := 0; i < len(manifest[0].Layers); i++ {
		tlayer := clairLayer{Hash: config.Rootfs.Diff_ids[i], Uri: ("http://172.17.0.1:9279/" + manifest[0].Layers[i])}
		cm.Layers = append(cm.Layers, tlayer)
	}
	return &cm
}

// readManifestFile reads the local manifest.json
func readManifestFile(path string) []manifestJSON {
	manifestFile := path + "/manifest.json"
	logger.Infof("opening manifest file %s", manifestFile)
	mf, err := os.Open(manifestFile)
	if err != nil {
		logger.Fatalf("Could not read Docker image layers: could not open [%s]: %v", manifestFile, err)
	}
	defer mf.Close()

	return parseAndValidateManifestFile(mf)
}

// parseAndValidateManifestFile parses the manifest.json file and validates it
func parseAndValidateManifestFile(manifestFile io.Reader) []manifestJSON {
	var manifest []manifestJSON
	if err := json.NewDecoder(manifestFile).Decode(&manifest); err != nil {
		logger.Fatalf("Could not read Docker image layers: manifest.json is not json: %v", err)
	} else if len(manifest) != 1 {
		logger.Fatalf("Could not read Docker image layers: manifest.json is not valid")
	} else if len(manifest[0].Layers) == 0 {
		logger.Fatalf("Could not read Docker image layers: no layers can be found")
	}
	return manifest
}

// readConfigFile reads the local config <sha>.json
func getConfigFileShas(path, sha string) *configJSON {
	configFile := path + "/" + sha + ".json"
	logger.Infof("opening config file %s", configFile)
	mf, err := os.Open(configFile)
	if err != nil {
		logger.Fatalf("Could not read Docker image layers: could not open [%s]: %v", configFile, err)
	}
	defer mf.Close()

	var config configJSON
	if err := json.NewDecoder(mf).Decode(&config); err != nil {
		logger.Fatalf("Could not read Docker image layers: config.json is not json: %v", err)
	}

	return &config
}
