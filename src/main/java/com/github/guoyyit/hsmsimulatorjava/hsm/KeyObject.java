package com.github.guoyyit.hsmsimulatorjava.hsm;

import java.util.EnumSet;
import java.util.Set;

public class KeyObject {

    private String id;
    private String label;
    private KeyType keyType;
    private EnumSet<KeyUsage> usages = EnumSet.noneOf(KeyUsage.class);
    private boolean sensitive;
    private boolean extractable;
    private boolean destroyed;
    private byte[] privateMaterial;
    private byte[] publicMaterial;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public Set<KeyUsage> getUsages() {
        return usages;
    }

    public void setUsages(Set<KeyUsage> usages) {
        this.usages = usages == null
                ? EnumSet.noneOf(KeyUsage.class)
                : EnumSet.copyOf(usages);
    }

    public boolean isSensitive() {
        return sensitive;
    }

    public void setSensitive(boolean sensitive) {
        this.sensitive = sensitive;
    }

    public boolean isExtractable() {
        return extractable;
    }

    public void setExtractable(boolean extractable) {
        this.extractable = extractable;
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    public void setDestroyed(boolean destroyed) {
        this.destroyed = destroyed;
    }

    public byte[] getPrivateMaterial() {
        return privateMaterial;
    }

    public void setPrivateMaterial(byte[] privateMaterial) {
        this.privateMaterial = privateMaterial;
    }

    public byte[] getPublicMaterial() {
        return publicMaterial;
    }

    public void setPublicMaterial(byte[] publicMaterial) {
        this.publicMaterial = publicMaterial;
    }
}
