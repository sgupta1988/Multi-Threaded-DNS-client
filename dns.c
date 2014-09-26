#include<stdio.h> 
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>   
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <pthread.h>

#define DNS_SERVERS_TO_USE 2
#define CACHE_CAPACITY 100
#define HASH_BUCKETS CACHE_CAPACITY
#define QUEUE_NODES CACHE_CAPACITY

struct cache_node{
	char *str;
	int str_len;
	struct cache_node *hash_next;
	struct cache_node *next,*prev;
};

struct hash_table{
	int buckets;
	struct cache_node **arr;
};

struct cache_queue{
	int filled;
	int total_nodes;
	struct cache_node *front,*rear;
};

struct dns_fields{
	unsigned short id;
	unsigned char rd :1; 
	unsigned char tc :1; 
	unsigned char aa :1; 
	unsigned char opcode :4; 
	unsigned char qr :1; 
	unsigned char rcode :4;
	unsigned char cd :1; 
	unsigned char ad :1; 
	unsigned char z :1; 
	unsigned char ra :1; 
	unsigned short q_count; 
	unsigned short ans_count; 
	unsigned short auth_count; 
	unsigned short add_count; 
};

struct what_question{
	unsigned short qtype;
	unsigned short qclass;
};

#pragma pack(push, 1)
struct R_DATA{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

struct RES_RECORD{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

typedef struct{
	unsigned char *name;
	struct what_question *ques;
} QUERY;

struct hash_table *create_hash_table(int buckets);
struct cache_queue *create_cache_queue(int num_nodes);
struct cache_node *create_node(char *str);
int hash_key(char *str);
struct cache_node *check_hash_table(char *str);
int is_cache_full();
int is_cache_empty();
void enqueue(char *str);
void add_node_to_queue(struct cache_node *node);
void remove_node_from_queue(struct cache_node *node);
void move_node_to_front_of_queue(struct cache_node *node);
void add_node_to_hash_table(struct cache_node *node);
void remove_node_from_hash_table(struct cache_node *node);
void cache_init();
void cache_cleanup();
int access_cache(char *str);
void *worker_thread(void *t);
void name_to_dns(unsigned char*,unsigned char*);
unsigned char* read_data(unsigned char*,unsigned char*,int*);
void configure_dns_servers();

char *addr_main_file;
char *addr_main_file_max;
int num_threads;
long size_per_thread;
long left_size;
pthread_t thread[100];
pthread_attr_t attr;
pthread_mutex_t access_cache_mutex;
struct hash_table *ht;
struct cache_queue *cq;
char dns_servers[20][100];
int num_dns_servers;

void configure_dns_servers(){
	int i=0,max=0;

	num_dns_servers=DNS_SERVERS_TO_USE;//this many server will be active. server select dns by doing (dns_servers[tid%num_dns_server])
	max=20;//max size of dns server array
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"208.67.222.222");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"8.8.8.8");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"209.244.0.3");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"8.26.56.26");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"156.154.70.1");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"199.85.126.10");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"81.218.119.11");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"195.46.39.39");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"216.87.84.211");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"199.5.157.131");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"208.76.50.50");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"216.146.35.35");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"37.235.1.174");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"89.233.43.71");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"84.200.69.80");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"74.82.42.42");
	if(i<num_dns_servers && i<max)
		strcpy(dns_servers[i++],"109.69.8.51");
}

struct hash_table *create_hash_table(int buckets){
	struct hash_table *tmp=NULL;
	int i=0;

	tmp=(struct hash_table *)malloc(sizeof(struct hash_table));
	if(tmp==NULL){
		printf("\nHash Table Create failed");
		return tmp;
	}
	tmp->buckets=buckets;
	tmp->arr=(struct cache_node **)malloc(buckets*sizeof(struct cache_node *));
	if(tmp->arr==NULL){
		printf("\nHash Table Create failed buckets space");
		free(tmp);
		return NULL;
	}
	for(i=0;i<buckets;i++){
		tmp->arr[i]=NULL;
	}
	return tmp;
}

struct cache_queue *create_cache_queue(int num_nodes){
	struct cache_queue *tmp=NULL;

	tmp=(struct cache_queue *)malloc(sizeof(struct cache_queue));
	if(tmp==NULL){
		printf("\nQueue Create failed");
		return tmp;
	}
	tmp->filled=0;
	tmp->total_nodes=num_nodes;
	tmp->front=NULL;
	tmp->rear=NULL;
	return tmp;
}

struct cache_node *create_node(char *str){
	struct cache_node *tmp=NULL;

	if(str==NULL){
		printf("\n Create node null string");
		return NULL;
	}
	tmp=(struct cache_node *)malloc(sizeof(struct cache_node));
	if(tmp==NULL){
		printf("\ncache node Create failed");
		return tmp;
	}
	tmp->str_len=strlen(str);
	tmp->str=(char *)malloc(sizeof(char)*(tmp->str_len+1));
	if(tmp->str==NULL){
		printf("\ncache node create failed for string space");
		free(tmp);
		return NULL;
	}
	memset(tmp->str, '\0', sizeof(tmp->str_len+1));
	strcpy(tmp->str,str);
	tmp->hash_next=NULL;
	tmp->next=NULL;
	tmp->prev=NULL;
	return tmp;
}

int hash_key(char *str){
	int sum=0,index=0,i=0;

	if(str==NULL){
		printf("\n hash key failed");
		return -1;
	}
	for(i=0;i<strlen(str);i++){
		sum+=str[i];
	}
	index=sum%HASH_BUCKETS;
	return index;
}

struct cache_node *check_hash_table(char *str){
	int key;
	struct cache_node *node=NULL;

	if(str==NULL){
		printf("\n check hash failed Null arguments");
		return NULL;
	}
	key=hash_key(str);
	node=ht->arr[key];
	while(node!=NULL){
		if(strcmp(node->str,str)==0){
			return node;
		}
		node=node->hash_next;
	}
	return node;
}

int is_cache_full(){
	return cq->filled==cq->total_nodes;
}

int is_cache_empty(){
	return cq->filled==0;
}

void enqueue(char *str){
	struct cache_node *node=NULL,*remove_node=NULL;

	if(str==NULL)
		return;
	if(is_cache_full()){
		remove_node=cq->rear;
		remove_node_from_queue(remove_node);
		remove_node_from_hash_table(remove_node);
		free(remove_node->str);
		free(remove_node);
	}
	node=create_node(str);
	if(node==NULL){
		printf("\nCache Enqueue Failed");
		exit(1);
	}
	add_node_to_queue(node);
	add_node_to_hash_table(node);
}

void add_node_to_queue(struct cache_node *node){
	if(node==NULL)
		return;
	node->next=cq->front;
	if(is_cache_empty()){
		cq->front=node;
		cq->rear=node;
	}
	else{
		cq->front->prev=node;
		cq->front=node;
	}
	cq->filled+=1;
}

void remove_node_from_queue(struct cache_node *node){
	if(node==NULL || is_cache_empty())
		return;
	if(cq->front==cq->rear)
		cq->front=NULL;
	cq->rear=cq->rear->prev;
	if(cq->rear!=NULL)
		cq->rear->next=NULL;
	cq->filled-=1;
}

void move_node_to_front_of_queue(struct cache_node *node){
	node->prev->next=node->next;
	if(node->next!=NULL)
		node->next->prev=node->prev;
	if(node==cq->rear){
		cq->rear=node->prev;
		cq->rear->next=NULL;
	}
	node->next=cq->front;
	node->prev=NULL;
	node->next->prev=node;
	cq->front=node;
}

void add_node_to_hash_table(struct cache_node *node){
	int key;
	struct cache_node *head=NULL;

	if(node==NULL)
		return;
	key=hash_key(node->str);
	if(key<0)
		return;
	head=ht->arr[key];
	if(head==NULL){
		ht->arr[key]=node;
		return;
	}
	while(head->hash_next!=NULL){
		head=head->hash_next;
	}
	head->hash_next=node;
}

void remove_node_from_hash_table(struct cache_node *node){
	int key;
	struct cache_node *head=NULL,*prev=NULL;

	if(node==NULL || is_cache_empty())
		return;
	key=hash_key(node->str);
	if(key<0)
		return;
	head=ht->arr[key];
	if(head==NULL)
		return;
	if(head==node){
		ht->arr[key]=head->hash_next;
		return;
	}
	while(head!=NULL && head!=node){
		prev=head;
		head=head->hash_next;
	}
	if(head==NULL)
		return;
	prev->hash_next=head->hash_next;
}

void cache_init(){
	ht=create_hash_table(HASH_BUCKETS);
	cq=create_cache_queue(QUEUE_NODES);
	if(ht==NULL||cq==NULL){
		printf("\n Cache init failed");
		exit(1);
	}
}

void cache_cleanup(){
	struct cache_node *head=NULL,*remove_node=NULL;
	int i=0;

	for(i=0;i<HASH_BUCKETS;i++){
		head=ht->arr[i];
		while(head!=NULL){
			remove_node=head;
			remove_node_from_queue(remove_node);
			remove_node_from_hash_table(remove_node);
			free(remove_node->str);
			free(remove_node);
			head=head->hash_next;
		}		
	}
	free(ht->arr);
	free(ht);
	ht=NULL;
	free(cq);
	cq=NULL;
}

// 0 --> Cache miss 
// 1 --> Cache hit 
int access_cache(char *str){
	struct cache_node *node=NULL;

	node=check_hash_table(str);
	if(node==NULL){
		//	printf("\n MISS");
		enqueue(str);
		return 0;
	}
	else if(node!=cq->front){
		move_node_to_front_of_queue(node);
	}   
	//printf("\n HIT");
	return 1;
}

void name_to_dns(unsigned char* dns,unsigned char* host){
	int next=0,i;

	strcat((char*)host,".");
	for(i=0;i<strlen((char*)host);i++){
		if(host[i]=='.'){
			*dns++=i-next;
			for(;next<i;next++){
				*dns++=host[next];
			}
			next++; 
		}
	}
	*dns++='\0';
}

u_char* read_data(unsigned char* reader,unsigned char* buffer,int* count){
	unsigned char *data;
	unsigned int p=0,next=0,offset;
	int i , j;

	*count = 1;
	data=(unsigned char*)malloc(300);
	data[0]='\0';
	while(*reader!=0){
		if(*reader>=192){
			offset = (*reader)*256 + *(reader+1) - 49152;
			reader = buffer + offset - 1;
			next = 1; 
		}
		else{
			data[p++]=*reader;
		}
		reader = reader+1;
		if(next==0){
			*count = *count + 1;
		}
	}
	data[p]='\0'; 
	if(next==1){
		*count = *count + 1; 
	}
	for(i=0;i<(int)strlen((const char*)data);i++){
		p=data[i];
		for(j=0;j<(int)p;j++){
			data[i]=data[i+1];
			i=i+1;
		}
		data[i]='.';
	}
	data[i-1]='\0'; 
	return data;
}

void *worker_thread(void *arg){
	unsigned char buf1[65536],*qname,*reader,*tmp,*buf;
	int i,j,end_tmp,s,ll=0,i_tmp=0,cache_output=0,dns_num=0;
	char *cur_str,*start_addr,*end_addr;
	long size=(long)size_per_thread,tid=(long)arg;
	struct sockaddr_in a,dest;
	FILE *fp;
	struct RES_RECORD answers[20],auth[20],addit[20]; 
	struct dns_fields *dns = NULL;
	struct what_question *qinfo = NULL;
	unsigned char file_host[100];
	unsigned char file_name[40];

	s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); 
	dest.sin_family=AF_INET;
	dest.sin_port=htons(53);
	dns_num=tid%num_dns_servers;
	dest.sin_addr.s_addr=inet_addr(dns_servers[dns_num]); 
	tmp=&buf1[0];
	buf=tmp;
	start_addr=addr_main_file+(tid-1)*size;
	if(tid!=1){
		while(*start_addr!='\n'){
			start_addr+=1;
		}
		start_addr+=1;
		while(*start_addr==' '){
			start_addr+=1;
		}
	}
	end_addr=addr_main_file+(tid)*size;
	if(left_size!=0 && tid==num_threads){
		end_addr=start_addr+left_size-1;
	}
	if(!(left_size!=0 && tid==num_threads)){
		while(*end_addr!='\n' && (end_addr<addr_main_file_max)){
			end_addr+=1;
		}
		end_addr+=1;
		while(*end_addr==' ' && (end_addr<addr_main_file_max)){
			end_addr+=1;
		}
	}
	memset(file_name,'\0',sizeof(file_name));
	sprintf(file_name, "thread_%d",(int)tid);
	fp=fopen(file_name,"a+");
	i_tmp=0;
	while(start_addr<end_addr){
		buf=tmp;
		dns=(struct dns_fields *)buf;
		dns->id=(unsigned short) ((i_tmp)+tid)%65000;
		dns->qr=0; 
		dns->opcode=0; 
		dns->aa=0; 
		dns->tc=0; 
		dns->rd=1; 
		dns->ra=0; 
		dns->z=0;
		dns->ad=0;
		dns->cd=0;
		dns->rcode=0;
		dns->q_count=htons(1); 
		dns->ans_count=0;
		dns->auth_count=0;
		dns->add_count=0;
		i_tmp++;
		memset(file_host,'\0',sizeof(file_host));
		for(i=0;i<90;i++){
			file_host[i]=*start_addr;
			if(*start_addr=='\n'){
				file_host[i]='\0';
				start_addr+=1;
				break;
			}
			start_addr+=1;
		}
		file_host[i-1]='\0';
		while(*start_addr==' '){
			start_addr+=1;
		}
		pthread_mutex_lock(&access_cache_mutex);
		cache_output=access_cache(file_host);
		pthread_mutex_unlock(&access_cache_mutex);
		if(cache_output==1)
			continue;
		qname =(unsigned char*)&buf[sizeof(struct dns_fields)];
		name_to_dns(qname,file_host);
		qinfo=(struct what_question*)&buf[sizeof(struct dns_fields)+(strlen((const char*)qname)+1)]; 
		qinfo->qtype=htons(1); 
		qinfo->qclass = htons(1); 
		if(sendto(s,(char*)buf,sizeof(struct dns_fields)+(strlen((const char*)qname)+1)+sizeof(struct what_question),0,(struct sockaddr*)&dest,sizeof(dest)) < 0){
			perror("sendto failed");
		}
		i = sizeof dest;
		if(recvfrom(s,(char*)buf,65536,0,(struct sockaddr*)&dest,(socklen_t*)&i)<0){
			perror("recvfrom failed");
		}
		dns=(struct dns_fields*)buf;
		reader=&buf[sizeof(struct dns_fields)+(strlen((const char*)qname)+1)+sizeof(struct what_question)];
		end_tmp=0;
		ll=0;
		for(i=0;i<ntohs(dns->ans_count);i++){
			answers[i].name=read_data(reader,buf,&end_tmp);
			reader=reader + end_tmp;
			if(ll==0){
				fprintf(fp,"%s\t\t",answers[i].name);
			}
			answers[i].resource=(struct R_DATA*)(reader);
			reader=reader+sizeof(struct R_DATA);
			if(ntohs(answers[i].resource->type)==1){
				unsigned char tmp1[ntohs(answers[i].resource->data_len)+1];
				answers[i].rdata=(unsigned char*)tmp1;
				for(j=0;j<ntohs(answers[i].resource->data_len);j++){
					answers[i].rdata[j]=reader[j];
				}
				answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
				reader = reader + ntohs(answers[i].resource->data_len);
				long *p;
				p=(long*)answers[i].rdata;
				a.sin_addr.s_addr=(*p); 
				if(ll==0){
					fprintf(fp,"%s",inet_ntoa(a.sin_addr));
				}
				else{
					fprintf(fp,"%s\n",inet_ntoa(a.sin_addr));
				}
				if(ll==1 && i<ntohs(dns->ans_count)-1){
					fprintf(fp,"%s\t\t",cur_str);
				}
			}
			else{
				answers[i].rdata=read_data(reader,buf,&end_tmp);
				reader = reader + end_tmp;
				ll=1;
				cur_str=answers[i].name;
			}
			if(ll==0){
				fprintf(fp,"\n");
			}
		}
		fflush(fp);
	}
	fflush(fp);
	fclose(fp);
	ll=0;
	pthread_exit((void*) arg);
}

int main(int argc,char *argv[]){
	FILE *fp_output,*fp_thread;
	struct stat s,thread_s;
	int fd,rc;
	long t,size,tid,thread_file_size;
	void *status;
	char *copy_buf;
	unsigned char file_name[40],output_file[40];

	cache_init();
	printf("\n Enter number of threads to create :");
	scanf("%d",&num_threads);
	printf("\n Enter name of output file :");
	scanf("%s",(char *)&output_file);
	tid=1;
	fd=open("hostnames",O_RDONLY);
	fstat(fd, &s);
	size=s.st_size;
	addr_main_file=mmap(0,s.st_size,PROT_READ,MAP_PRIVATE,fd,0);
	addr_main_file_max=addr_main_file+size;
	srand(time(NULL));
	configure_dns_servers();
	if(num_dns_servers<0){
		printf("\n Configure dns error");
		exit(1);
	}
	size_per_thread=0;
	left_size=0;
	size_per_thread=size/num_threads;
	left_size=size%num_threads;
	if(left_size!=0)
		num_threads+=1;	
	printf("\nsize_per_thread=[%ld]",size_per_thread);
	printf("\nsize=[%ld]",size);
	printf("\nleft_size=[%ld]",left_size);
	printf("\nnum_threads=[%d]",num_threads);
	pthread_attr_init(&attr);
	pthread_mutex_init(&access_cache_mutex, NULL);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_JOINABLE);
	for(t=1;t<=num_threads;t++){
		printf("creating thread %d\n",(int)t);
		rc=pthread_create(&thread[t], &attr,worker_thread,(void *)t); 
		if(rc){
			printf("ERROR:: return code from pthread_create() is %d\n", rc);
			exit(-1);
		}
	}
	pthread_attr_destroy(&attr);
	for(t=1;t<=num_threads;t++){
		rc=pthread_join(thread[t],&status);
		if(rc){
			printf("ERROR:: return code from pthread_join() is %d\n", rc);
			exit(-1);
		}
		printf("completed join with thread %ld having a status of %ld\n",t,(long)status);
	}
	printf("Threads work completed\n");
	pthread_mutex_destroy(&access_cache_mutex);
	munmap(addr_main_file,size);
	addr_main_file=NULL;
	addr_main_file_max=NULL;
	close(fd);
	cache_cleanup();
	fp_output=NULL;
	if((fp_output=fopen(output_file,"a+"))==NULL){
		printf("Failed opening output file \n");
		exit(1);
	}
	copy_buf=(char *)malloc(sizeof(char)*1024*1024*1024);
	for(t=1;t<=num_threads;t++){
		fd=-1;
		fp_thread=NULL;
		thread_file_size=0;
		memset(file_name,'\0',sizeof(file_name));
		sprintf(file_name, "thread_%d",(int)t);
		fd=open(file_name,O_RDONLY);
		fstat(fd, &thread_s);
		thread_file_size=thread_s.st_size;
		close(fd);
		fp_thread=fopen(file_name,"r+");
		while(thread_file_size>0){
			if(size>=(1024*1024*1024)){            
				fread(copy_buf,(1024*1024*1024), 1, fp_thread);
				fwrite(copy_buf,(1024*1024*1024),1,fp_output);
				thread_file_size-=(1024*1024*1024);               
			}
			else{
				fread(copy_buf,thread_file_size, 1,fp_thread);
				fwrite(copy_buf,thread_file_size,1,fp_output);
				thread_file_size=0;               
			}
		}
		fflush(fp_thread);
		fclose(fp_thread);
		unlink(file_name);
		fflush(fp_output);
	}
	fflush(fp_output);
	fclose(fp_output);
	free(copy_buf);
	return 0;
}

