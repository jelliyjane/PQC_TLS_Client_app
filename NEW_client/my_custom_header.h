#ifndef MY_CUSTOM_HEADER_H
#define MY_CUSTOM_HEADER_H

typedef struct {
	double appdata_time;
	double handshake_time;
}TIME_INFO;

TIME_INFO get_time_info(void);

#endif //MY_CUSTOM_HEADER_H
