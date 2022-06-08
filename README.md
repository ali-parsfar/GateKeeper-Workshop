# GateKeeper-Workshop :)
```
```
# #################################################################################
# Create "gatekeeper" cluster with eksctl :
# #################################################################################

```s
GateKeeper-WorkShop % eksctl create cluster -f Cluster.yaml
2022-06-08 09:31:50 [ℹ]  eksctl version 0.97.0
2022-06-08 09:31:50 [ℹ]  using region ap-southeast-2
2022-06-08 09:31:50 [ℹ]  setting availability zones to [ap-southeast-2b ap-southeast-2a ap-southeast-2c]
..
.. ..
2022-06-08 09:50:42 [ℹ]  cluster should be functional despite missing (or misconfigured) client binaries
2022-06-08 09:50:42 [✔]  EKS cluster "opa-eks-22" in "ap-southeast-2" region is ready

GateKeeper-WorkShop % aws eks update-kubeconfig --name opa-eks-22
Added new context arn:aws:eks:ap-southeast-2:XXXXXXXXXXX:cluster/opa-eks-22 to /Users/parsfaa/.kube/config                         

GateKeeper-WorkShop % k get node
NAME                                                STATUS   ROLES    AGE   VERSION
ip-192-168-25-67.ap-southeast-2.compute.internal    Ready    <none>   59m   v1.22.6-eks-7d68063
ip-192-168-60-229.ap-southeast-2.compute.internal   Ready    <none>   59m   v1.22.6-eks-7d68063
ip-192-168-83-170.ap-southeast-2.compute.internal   Ready    <none>   60m   v1.22.6-eks-7d68063                                                                          
GateKeeper-WorkShop % 
```


```
```
# #################################################################################
# Install gatekeeper with helm :
# #################################################################################

### https://open-policy-agent.github.io/gatekeeper/website/docs/install/

```s
# 1- Adding Helm repo to your terminal :
GateKeeper-WorkShop %  helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
"gatekeeper" has been added to your repositories

# 2- List Helm repos in your terminal :
GateKeeper-WorkShop %  helm repo ls |  grep gatekeeper                                               
gatekeeper              https://open-policy-agent.github.io/gatekeeper/charts 

# 3- Install gatekeeper with Helm         
GateKeeper-WorkShop %  helm install gatekeeper/gatekeeper \       
--name-template=gatekeeper \
--namespace gatekeeper-system \
--create-namespace
W0530 11:12:14.163119   29399 warnings.go:67] policy/v1beta1 PodSecurityPolicy is deprecated in v1.21+, unavailable in v1.25+
W0530 11:12:14.403257   29399 warnings.go:67] spec.template.metadata.annotations[container.seccomp.security.alpha.kubernetes.io/manager]: deprecated since v1.19; use the "seccompProfile" field instead
NAME: gatekeeper
LAST DEPLOYED: Mon May 30 11:12:02 2022
NAMESPACE: gatekeeper-system
STATUS: deployed
REVISION: 1
TEST SUITE: None

# Looking at installed resources :
GateKeeper-WorkShop %  k -n gatekeeper-system get pod
NAME                                             READY   STATUS    RESTARTS   AGE
gatekeeper-audit-6bd4b8f4d4-drsv5                1/1     Running   0          9m24s
gatekeeper-controller-manager-77768dcc76-ncdcj   1/1     Running   0          9m24s
gatekeeper-controller-manager-77768dcc76-shgtw   1/1     Running   0          9m24s
gatekeeper-controller-manager-77768dcc76-vbkxr   1/1     Running   0          9m24s


GateKeeper-WorkShop %  k get crd | grep "NAME\|gatekeeper"

NAME                                                 CREATED AT
assign.mutations.gatekeeper.sh                       2022-06-08T02:18:54Z
assignmetadata.mutations.gatekeeper.sh               2022-06-08T02:18:54Z
configs.config.gatekeeper.sh                         2022-06-08T02:18:54Z
constraintpodstatuses.status.gatekeeper.sh           2022-06-08T02:18:54Z
constrainttemplatepodstatuses.status.gatekeeper.sh   2022-06-08T02:18:54Z
constrainttemplates.templates.gatekeeper.sh          2022-06-08T02:18:54Z
modifyset.mutations.gatekeeper.sh                    2022-06-08T02:18:54Z
mutatorpodstatuses.status.gatekeeper.sh              2022-06-08T02:18:54Z
providers.externaldata.gatekeeper.sh                 2022-06-08T02:18:55Z
GateKeeper-WorkShop %  

```




```
```
# #################################################################################
# Have a look to installed components with HELM :
# #################################################################################

```s
GateKeeper-WorkShop % ls /Users/parsfaa/Library/Caches/helm/repository/gatekeeper-3.8.1.tgz
/Users/parsfaa/Library/Caches/helm/repository/gatekeeper-3.8.1.tgz
                                                                                                                             
GateKeeper-WorkShop % 

ateKeeper-WorkShop % tar xvfz /Users/parsfaa/Library/Caches/helm/repository/gatekeeper-3.8.1.tgz 
x gatekeeper/Chart.yaml
x gatekeeper/values.yaml
x gatekeeper/templates/_helpers.tpl
x gatekeeper/templates/gatekeeper-admin-podsecuritypolicy.yaml
x gatekeeper/templates/gatekeeper-admin-serviceaccount.yaml
x gatekeeper/templates/gatekeeper-audit-deployment.yaml
x gatekeeper/templates/gatekeeper-controller-manager-deployment.yaml
x gatekeeper/templates/gatekeeper-controller-manager-poddisruptionbudget.yaml
x gatekeeper/templates/gatekeeper-critical-pods-resourcequota.yaml
x gatekeeper/templates/gatekeeper-manager-role-clusterrole.yaml
x gatekeeper/templates/gatekeeper-manager-role-role.yaml
x gatekeeper/templates/gatekeeper-manager-rolebinding-clusterrolebinding.yaml
x gatekeeper/templates/gatekeeper-manager-rolebinding-rolebinding.yaml
x gatekeeper/templates/gatekeeper-mutating-webhook-configuration-mutatingwebhookconfiguration.yaml
x gatekeeper/templates/gatekeeper-validating-webhook-configuration-validatingwebhookconfiguration.yaml
x gatekeeper/templates/gatekeeper-webhook-server-cert-secret.yaml
x gatekeeper/templates/gatekeeper-webhook-service-service.yaml
x gatekeeper/templates/namespace-post-install.yaml
x gatekeeper/templates/upgrade-crds-hook.yaml
x gatekeeper/templates/webhook-configs-pre-delete.yaml
x gatekeeper/.helmignore
x gatekeeper/README.md
x gatekeeper/crds/assign-customresourcedefinition.yaml
x gatekeeper/crds/assignmetadata-customresourcedefinition.yaml
x gatekeeper/crds/config-customresourcedefinition.yaml
x gatekeeper/crds/constraintpodstatus-customresourcedefinition.yaml
x gatekeeper/crds/constrainttemplate-customresourcedefinition.yaml
x gatekeeper/crds/constrainttemplatepodstatus-customresourcedefinition.yaml
x gatekeeper/crds/modifyset-customresourcedefinition.yaml
x gatekeeper/crds/mutatorpodstatus-customresourcedefinition.yaml
x gatekeeper/crds/provider-customresourcedefinition.yaml
            
GateKeeper-WorkShop % 
```

# #######################################################################################
# One of the reliable resources for having more information about GateKeeper is here :
# #######################################################################################

### https://open-policy-agent.github.io/gatekeeper/website/docs

### https://github.com/open-policy-agent/gatekeeper-library

You can clone this libray and use pre-made templates for your cluster:

```s
GateKeeper-WorkShop % git clone https://github.com/open-policy-agent/gatekeeper-library.git
Cloning into 'gatekeeper-library'...
remote: Enumerating objects: 2290, done.
remote: Counting objects: 100% (1019/1019), done.
remote: Compressing objects: 100% (532/532), done.
remote: Total 2290 (delta 585), reused 688 (delta 466), pack-reused 1271
Receiving objects: 100% (2290/2290), 436.68 KiB | 828.00 KiB/s, done.
Resolving deltas: 100% (1218/1218), done.

GateKeeper-WorkShop % ls gatekeeper-library/library/general 
allowedrepos                            containerresources                      poddisruptionbudget
automount-serviceaccount-token          disallowanonymous                       replicalimits
block-endpoint-edit-default-role        disallowedtags                          requiredannotations
block-nodeport-services                 externalip                              requiredlabels
block-wildcard-ingress                  httpsonly                               requiredprobes
containerlimits                         imagedigests                            uniqueingresshost
containerrequests                       kustomization.yaml                      uniqueserviceselector
containerresourceratios                 noupdateserviceaccount
GateKeeper-WorkShop %  
```


```
```
# #################################################################################
# Example One = 
# #################################################################################
A new requierment for the cluster, we like to have a Constraint , for reqired "owner" label for namespaces.

## Constraint for reqired "owner" label for namespaces

```yaml
GateKeeper-WorkShop % cat templates/required-lables/must-have-owner.yaml 
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: all-must-have-owner
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    message: "All namespaces must have an `owner` label that points to your company username"
    labels:
      - key: owner
        allowedRegex: "^[a-zA-Z]+.amazon.com$"%                                                                                                             
GateKeeper-WorkShop % 
```


## Constraint Template for required lebel :

```yaml
GateKeeper-WorkShop % cat templates/required-lables/requiredlabels_template.yaml 
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
  annotations:
    description: >-
      Requires resources to contain specified labels, with values matching
      provided regular expressions.
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            message:
              type: string
            labels:
              type: array
              description: >-
                A list of labels and values the object must specify.
              items:
                type: object
                properties:
                  key:
                    type: string
                    description: >-
                      The required label.
                  allowedRegex:
                    type: string
                    description: >-
                      If specified, a regular expression the annotation's value
                      must match. The value must contain at least one match for
                      the regular expression.
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        get_message(parameters, _default) = msg {
          not parameters.message
          msg := _default
        }
        get_message(parameters, _default) = msg {
          msg := parameters.message
        }
        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_].key}
          missing := required - provided
          count(missing) > 0
          def_msg := sprintf("you must provide labels: %v", [missing])
          msg := get_message(input.parameters, def_msg)
        }
        violation[{"msg": msg}] {
          value := input.review.object.metadata.labels[key]
          expected := input.parameters.labels[_]
          expected.key == key
          # do not match if allowedRegex is not defined, or is an empty string
          expected.allowedRegex != ""
          not re_match(expected.allowedRegex, value)
          def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
          msg := get_message(input.parameters, def_msg)
GateKeeper-WorkShop % 
```

## Testing the required labels Constraint with creating new namespace :
```s
# 1- Appying constraint to our cluster:
GateKeeper-WorkShop % k apply -f templates/required-lables 
k8srequiredlabels.constraints.gatekeeper.sh/all-must-have-owner created
constrainttemplate.templates.gatekeeper.sh/k8srequiredlabels unchanged


# 2- Try to create a namespace without lable :
GateKeeper-WorkShop % k create ns test
Error from server (Forbidden): admission webhook "validation.gatekeeper.sh" denied the request: [all-must-have-owner] All namespaces must have an `owner` label that points to your company username
GateKeeper-WorkShop %

#  3- Try to add namespace with owner label , is working:
GateKeeper-WorkShop % k apply -f templates/required-lables/test/test_namespace.yaml
namespace/test created
GateKeeper-WorkShop % 

GateKeeper-WorkShop %  k get ns --show-labels
NAME                STATUS   AGE    LABELS
default             Active   3h1m   kubernetes.io/metadata.name=default
gatekeeper-system   Active   138m   admission.gatekeeper.sh/ignore=no-self-managing,kubernetes.io/metadata.name=gatekeeper-system,name=gatekeeper-system
kube-node-lease     Active   3h1m   kubernetes.io/metadata.name=kube-node-lease
kube-public         Active   3h1m   kubernetes.io/metadata.name=kube-public
kube-system         Active   3h1m   kubernetes.io/metadata.name=kube-system
test                Active   13s    kubernetes.io/metadata.name=test,owner=parsfaa.amazon.com

# 4- Have an idea about the Violations for our constraint with get and describe commands:
GateKeeper-WorkShop % k get constraint,constrainttemplate
NAME                                                              ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8srequiredlabels.constraints.gatekeeper.sh/all-must-have-owner                        5

NAME                                                           AGE
constrainttemplate.templates.gatekeeper.sh/k8srequiredlabels   5m8s
GateKeeper-WorkShop % 
```


## We can have more information withing logs, Audit is checking the resources for new Violations changes in the cluster:
```s
# Audit LOgs 
emplates % kubectl logs -l control-plane=audit-controller -n gatekeeper-system | grep owner
{"level":"info","ts":1654484920.0549848,"logger":"controller","msg":"updated constraint status violations","process":"audit","audit_id":"2022-06-06T03:08:36Z","constraintName":"all-must-have-owner","count":5}
{"level":"info","ts":1654484920.0554924,"logger":"controller","msg":"handling constraint update","process":"constraint_controller","instance":{"apiVersion":"constraints.gatekeeper.sh/v1beta1","kind":"K8sRequiredLabels","name":"all-must-have-owner"}}
templates % 

# Controller Logs
templates % kubectl logs -l control-plane=controller-manager -n gatekeeper-system | grep owner 
{"level":"info","ts":1654484920.0543115,"logger":"controller","msg":"handling constraint update","process":"constraint_controller","instance":{"apiVersion":"constraints.gatekeeper.sh/v1beta1","kind":"K8sRequiredLabels","name":"all-must-have-owner"}}
templates % 
```

```
```
# #################################################################################
# Example Two = 
# #################################################################################

A new requierment for the cluster, we like to have a Images from our ECR repo in this account, only .

## Constraint for only permited REPO is my ECR:
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: repo-is-my-ecr
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "default"
  parameters:
    repos:
      - "XXXXXXXXXXX.dkr.ecr.ap-southeast-2.amazonaws.com/"
```


## ConstraintTemplate for reqired REPO restriction:

```yaml
GateKeeper-WorkShop % cat k8srequiredlabels_ConstrainTemplate.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
  annotations:
    description: >-
      Requires container images to begin with a string from the specified list.
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            repos:
              description: The list of prefixes a container image is allowed to have.
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedrepos

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("container <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("initContainer <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.ephemeralContainers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("ephemeralContainer <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }
```

```s
# Creating a pod for chacking the violation after activating constraint:
GateKeeper-WorkShop % k run old-pod --image=nginx 
pod/old-pod created
GateKeeper-WorkShop % k get pod
NAME      READY   STATUS    RESTARTS   AGE
old-pod   1/1     Running   0          2m17s


# Applying constraint for only my-ecr-repo :
GateKeeper-WorkShop % k apply -f templates/Only-allowed-repos
constrainttemplate.templates.gatekeeper.sh/k8sallowedrepos unchanged
k8sallowedrepos.constraints.gatekeeper.sh/repo-is-my-ecr created
GateKeeper-WorkShop % 

# Not working with other repos
GateKeeper-WorkShop %  k run test --image=nginx
Error from server (Forbidden): admission webhook "validation.gatekeeper.sh" denied the request: [repo-is-my-ecr] container <test> has an invalid image repo <nginx>, allowed repos are ["XXXXXXXXXXX.dkr.ecr.ap-southeast-2.amazonaws.com/"]
GateKeeper-WorkShop %

# If we had already running pod , with images out of my-repo , we can check its violation,  with describe on the constraint :
GateKeeper-WorkShop % k describe k8sallowedrepos.constraints.gatekeeper.sh/repo-is-my-ecr | grep -A5 "Violations:"
  Total Violations:  1
  Violations:
    Enforcement Action:  deny
    Kind:                Pod
    Message:             container <old-pod> has an invalid image repo <nginx>, allowed repos are ["XXXXXXXXXXX.dkr.ecr.ap-southeast-2.amazonaws.com/"]
    Name:                old-pod
    Namespace:           default
GateKeeper-WorkShop %  

# Only with my ecr repo is working
GateKeeper-WorkShop % k run test --image=XXXXXXXXXXX.dkr.ecr.ap-southeast-2.amazonaws.com/nginx:1.19
pod/test created

GateKeeper-WorkShop % k get pod
NAME   READY   STATUS              RESTARTS   AGE
test   0/1     ContainerCreating   0          4s

GateKeeper-WorkShop % k get pod
NAME      READY   STATUS    RESTARTS   AGE
test      1/1     Running   0          10s
old-pod   1/1     Running   0          5m27s
GateKeeper-WorkShop % 


#  Check number of Violation detected for this constraint :
GateKeeper-WorkShop % k get constraint
NAME                                                                            ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8sallowedrepos.constraints.gatekeeper.sh/repo-is-my-ecr                                             1
k8srequiredlabels.constraints.gatekeeper.sh/all-must-have-owner                                      5
GateKeeper-WorkShop % 
```



```
```
# #################################################################################
# Example Three = 
# #################################################################################

### As we can see in above examples the admission controller is using the resource parameters for determining the rule and creating messages. 
### What if for the rule we need to run a query on all cluster to check all resources , like checking all cluster labels before creating a new selector to make sure it is unique.

Requires Services to have unique selectors within a namespace. Selectors are considered the same if they have identical keys and values. Selectors may share a key/value pair so long as there is at least one distinct key/value pair between them.

### Important = For this policy to work, you need to enable data replication as described 

https://docs.rafay.co/recipes/governance/use_opa/#data-replication

Some constraints are impossible to write without access to more state than just the object under test. For example, it is impossible to know if an ingress's hostname is unique among all ingresses unless a rule has access to all other ingresses. To make such rules possible, we need to enable syncing of data into OPA. 
## Kubernetes data can be replicated into OPA via the sync config resource.

```yaml
apiVersion: config.gatekeeper.sh/v1alpha1
kind: Config
metadata:
  name: config
  namespace: "gatekeeper-system"
spec:
  sync:
    syncOnly:
      - group: ""
        version: "v1"
        kind: "Namespace"
      - group: ""
        version: "v1"
        kind: "Pod"
      - group: "extensions"
        version: "v1beta1"
        kind: "Ingress"
      - group: "networking.k8s.io"
        version: "v1beta1"
        kind: "Ingress"
```

After applying the above resource to the cluster, resources for pods, namespaces, ingress data will be synced into OPA.



## Constraint for re-inforce for unique Selector for Services in my namespace:
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sUniqueServiceSelector
metadata:
  name: unique-service-selector
  labels:
    owner: parsfaa@amazon.com

```


## ConstraintTemplate for reqired REPO restriction:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8suniqueserviceselector
  annotations:
    description: >-
      Requires Services to have unique selectors within a namespace.
      Selectors are considered the same if they have identical keys and values.
      Selectors may share a key/value pair so long as there is at least one
      distinct key/value pair between them.

      https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service
spec:
  crd:
    spec:
      names:
        kind: K8sUniqueServiceSelector
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8suniqueserviceselector

        make_apiversion(kind) = apiVersion {
          g := kind.group
          v := kind.version
          g != ""
          apiVersion = sprintf("%v/%v", [g, v])
        }

        make_apiversion(kind) = apiVersion {
          kind.group == ""
          apiVersion = kind.version
        }

        identical(obj, review) {
          obj.metadata.namespace == review.namespace
          obj.metadata.name == review.name
          obj.kind == review.kind.kind
          obj.apiVersion == make_apiversion(review.kind)
        }

        flatten_selector(obj) = flattened {
          selectors := [s | s = concat(":", [key, val]); val = obj.spec.selector[key]]
          flattened := concat(",", sort(selectors))
        }

        violation[{"msg": msg}] {
          input.review.kind.kind == "Service"
          input.review.kind.version == "v1"
          input.review.kind.group == ""
          input_selector := flatten_selector(input.review.object)
          other := data.inventory.namespace[namespace][_]["Service"][name]
          not identical(other, input.review)
          other_selector := flatten_selector(other)
          input_selector == other_selector
          msg := sprintf("same selector as service <%v> in namespace <%v>", [name, namespace])
        }
```

```s
# Creating an old service for chacking the violation after activating constraint:
GateKeeper-WorkShop % k create deployment old-dep --image=XXXXXXXXXXX.dkr.ecr.ap-southeast-2.amazonaws.com/nginx:1.19 --replicas=2
deployment.apps/old-dep created
GateKeeper-WorkShop % k expose deploy old-dep --port=80 --target-port=80 
service/old-dep exposed
GateKeeper-WorkShop % k describe  svc old-dep | grep -i selector 
Selector:          app=old-dep

GateKeeper-WorkShop % k -n test create deployment old-dep --image=XXXXXXXXXXX.dkr.ecr.ap-southeast-2.amazonaws.com/nginx:1.19 --replicas=2
deployment.apps/old-dep created
GateKeeper-WorkShop % k -n test expose deploy old-dep --port=80 --target-port=80 
service/old-dep exposed
GateKeeper-WorkShop % k -n test describe  svc old-dep | grep -i selector 
Selector:          app=old-dep
GateKeeper-WorkShop % 


# Applying constraint for Unique Selector :
GateKeeper-WorkShop % k apply -f templates/Unique-SVC-Selector
constrainttemplate.templates.gatekeeper.sh/k8suniqueserviceselector unchanged
k8suniqueserviceselector.constraints.gatekeeper.sh/unique-service-selector created
config.config.gatekeeper.sh/config created
GateKeeper-WorkShop %


# Not working if you want to create a service with used selector 
GateKeeper-WorkShop % k apply -f templates/Unique-SVC-Selector/test/new-dep_svc.yaml
Error from server (Forbidden): error when creating "templates/Unique-SVC-Selector/test/new-dep_svc.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [unique-service-selector] same selector as service <new-dep> in namespace <default>
[unique-service-selector] same selector as service <old-dep> in namespace <test>
GateKeeper-WorkShop % 


GateKeeper-WorkShop % k get constraint
NAME                                                                         ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8srequiredlabels.constraints.gatekeeper.sh/all-must-have-owner                                   5
k8sallowedrepos.constraints.gatekeeper.sh/repo-is-my-ecr                                          1
k8suniqueserviceselector.constraints.gatekeeper.sh/unique-service-selector                        2
GateKeeper-WorkShop % 


# If we had already running pod , with images out of my-repo , we can check its violation,  with describe on the constraint :
GateKeeper-WorkShop % k describe k8suniqueserviceselector.constraints.gatekeeper.sh/unique-service-selector | grep -A15 "Violations:"
  Total Violations:  2
  Violations:
    Enforcement Action:  deny
    Kind:                Service
    Message:             same selector as service <old-dep> in namespace <test>
    Name:                new-dep
    Namespace:           default
    Enforcement Action:  deny
    Kind:                Service
    Message:             same selector as service <new-dep> in namespace <default>
    Name:                old-dep
    Namespace:           test
Events:                  <none>

```
