# API Reference

## Packages
- [k8s.ovn.org/v1](#k8sovnorgv1)


## k8s.ovn.org/v1

Package v1 contains API Schema definitions for the RouteAdvertisements v1 API
group

### Resource Types
- [RouteAdvertisements](#routeadvertisements)
- [RouteAdvertisementsList](#routeadvertisementslist)



#### AdvertisementType

_Underlying type:_ _string_

AdvertisementType determines the type of advertisement.

_Validation:_
- Enum: [PodNetwork EgressIP]

_Appears in:_
- [RouteAdvertisementsSpec](#routeadvertisementsspec)

| Field | Description |
| --- | --- |
| `PodNetwork` | PodNetwork determines that the pod network is advertised.<br /> |
| `EgressIP` | EgressIP determines that egress IPs are being advertised.<br /> |


#### RouteAdvertisements



RouteAdvertisements is the Schema for the routeadvertisements API



_Appears in:_
- [RouteAdvertisementsList](#routeadvertisementslist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `k8s.ovn.org/v1` | | |
| `kind` _string_ | `RouteAdvertisements` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RouteAdvertisementsSpec](#routeadvertisementsspec)_ |  |  |  |
| `status` _[RouteAdvertisementsStatus](#routeadvertisementsstatus)_ |  |  |  |


#### RouteAdvertisementsList



RouteAdvertisementsList contains a list of RouteAdvertisements





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `k8s.ovn.org/v1` | | |
| `kind` _string_ | `RouteAdvertisementsList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[RouteAdvertisements](#routeadvertisements) array_ |  |  |  |


#### RouteAdvertisementsSpec



RouteAdvertisementsSpec defines the desired state of RouteAdvertisements



_Appears in:_
- [RouteAdvertisements](#routeadvertisements)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetVRF` _string_ | targetVRF determines which VRF the routes should be advertised in. |  | Optional: \{\} <br /> |
| `networkSelectors` _[NetworkSelectors](#networkselectors)_ | networkSelectors determines which network routes should be advertised.<br />Only ClusterUserDefinedNetworks and the default network can be selected. |  | Required: \{\} <br /> |
| `nodeSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#labelselector-v1-meta)_ | nodeSelector limits the advertisements to selected nodes. This field<br />follows standard label selector semantics. |  | Required: \{\} <br /> |
| `frrConfigurationSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#labelselector-v1-meta)_ | frrConfigurationSelector determines which FRRConfigurations will the<br />OVN-Kubernetes driven FRRConfigurations be based on. This field follows<br />standard label selector semantics. |  | Required: \{\} <br /> |
| `advertisements` _[AdvertisementType](#advertisementtype) array_ | advertisements determines what is advertised. |  | Enum: [PodNetwork EgressIP] <br />MaxItems: 2 <br />MinItems: 1 <br />Required: \{\} <br /> |


#### RouteAdvertisementsStatus



RouteAdvertisementsStatus defines the observed state of RouteAdvertisements.
It should always be reconstructable from the state of the cluster and/or
outside world.



_Appears in:_
- [RouteAdvertisements](#routeadvertisements)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `status` _string_ | status is a concise indication of whether the RouteAdvertisements<br />resource is applied with success. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#condition-v1-meta) array_ | conditions is an array of condition objects indicating details about<br />status of RouteAdvertisements object. |  | Optional: \{\} <br /> |


