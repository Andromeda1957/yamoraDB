#ifndef YAMORA_TEST_CLUSTER_APPLICATION_FIXTURE_H
#define YAMORA_TEST_CLUSTER_APPLICATION_FIXTURE_H
#include "../src/consensus/cluster.h"
typedef struct ApplicationFixture ApplicationFixture;
ApplicationFixture *yd_test_application_new(YDRaftCluster *cluster, const char *root,
                                            unsigned timeout);
bool yd_test_application_command(ApplicationFixture *fixture, const char *command);
bool yd_test_application_sync(void);
void yd_test_application_close(ApplicationFixture *fixture);
void yd_test_application_worker_report(void);
#endif
