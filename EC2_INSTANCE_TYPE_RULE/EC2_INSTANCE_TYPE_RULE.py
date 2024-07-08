from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

APPLICABLE_RESOURCES = ['AWS::EC2::Instance']

class EC2_INSTANCE_TYPE_RULE(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        ###############################
        # Add your custom logic here. #
        ###############################

        instance_id = configuration_item.get("resourceId")

        ec2_client = client_factory.build_client("ec2")

        response = ec2_client.describe_instances(InstanceIds=[instance_id])

        instance = response['Reservations'][0]['Instances'][0]

        instance_type = instance['InstanceType']

        if instance_type == 't2.micro':
            return [Evaluation(ComplianceType.COMPLIANT)]
        
        annotation = "The EC2 instance type is different to t2.micro, making it noncompliant."
        return [Evaluation(ComplianceType.NON_COMPLIANT, annotation=annotation)]


    #def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
    #    pass

    def evaluate_parameters(self, rule_parameters):
        valid_rule_parameters = rule_parameters
        return valid_rule_parameters


################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = EC2_INSTANCE_TYPE_RULE()
    evaluator = Evaluator(my_rule, APPLICABLE_RESOURCES)
    return evaluator.handle(event, context)
